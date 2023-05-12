// Copyright 2023 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const bridgeIfName = "bridge"
const vxlanIfName = "vxlan"

type NetConf struct {
	types.NetConf
	Master string `json:"master"`
	VNI    int    `json:"vni"`
	Group  string `json:"group"`
}

func (nc *NetConf) GetName() string {
	return fmt.Sprintf("%s-%d", nc.Master, nc.VNI)
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadConf(args)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	vxlanNetNs, err := getVxLANNetNs(n)
	if err != nil {
		return fmt.Errorf("failed to create/get vxlan netns %q: %v", args.Netns, err)
	}

	err = createVeth(args.IfName, vxlanNetNs, netns)
	if err != nil {
		return fmt.Errorf("failed to create veth %q: %v", args.Netns, err)
	}

	podInterface, err := getInterface(args.IfName, netns)
	if err != nil {
		return fmt.Errorf("failed to get pod interface %q: %v", args.Netns, err)
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to execute IPAM delegate: %v", err)
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}
	for _, ipc := range result.IPs {
		// All addresses belong to the vlan interface
		ipc.Interface = current.Int(0)
	}

	result.Interfaces = []*current.Interface{podInterface}

	err = netns.Do(func(_ ns.NetNS) error {
		return ipam.ConfigureIface(args.IfName, result)
	})
	if err != nil {
		return err
	}

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadConf(args)
	if err != nil {
		return err
	}

	err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		err = ip.DelLinkByName(args.IfName)
		if err != nil && err == ip.ErrLinkNotFound {
			return nil
		}
		return err
	})

	if err != nil {
		//  if NetNs is passed down by the Cloud Orchestration Engine, or if it called multiple times
		// so don't return an error if the device is already removed.
		// https://github.com/kubernetes/kubernetes/issues/43014#issuecomment-287164444
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}

	return err
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("vxlan"))
}

func loadConf(args *skel.CmdArgs) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(args.StdinData, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.Master == "" {
		return nil, "", fmt.Errorf("\"master\" field is required. It specifies the host interface name to create the VxLAN for")
	}
	if n.VNI < 0 || n.VNI > 16777215 {
		return nil, "", fmt.Errorf("invalid VxLAN ID %d (must be between 0 and 16777215 inclusive)", n.VNI)
	}

	return n, n.CNIVersion, nil
}

func getInterface(ifName string, containerNs ns.NetNS) (*current.Interface, error) {
	var macAddr string
	err := containerNs.Do(func(_ ns.NetNS) error {
		podIf, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch interface %q: %v", ifName, err)
		}
		macAddr = podIf.Attrs().HardwareAddr.String()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &current.Interface{
		Name:    ifName,
		Sandbox: containerNs.Path(),
		Mac:     macAddr,
	}, nil
}

func createVeth(ifName string, vxlanNetNs netns.NsHandle, containerNs ns.NetNS) error {
	// Create Veth
	peerName, err := ip.RandomVethName()
	if err != nil {
		return err
	}
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:      ifName,
			Namespace: netlink.NsFd(int(containerNs.Fd())),
		},
		PeerName:      peerName,
		PeerNamespace: netlink.NsFd(vxlanNetNs),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}

	// Get peer from VxLAN/bridge net ns
	handle, err := netlink.NewHandleAt(vxlanNetNs)
	if err != nil {
		return err
	}
	peerLink, err := handle.LinkByName(peerName)
	if err != nil {
		return err
	}

	// Attach peer to the bridge
	bridge, err := handle.LinkByName(bridgeIfName)
	if err != nil {
		return err
	}
	err = handle.LinkSetMaster(peerLink, bridge)
	if err != nil {
		return err
	}
	err = handle.LinkSetUp(peerLink)
	if err != nil {
		return err
	}

	return nil
}

func getVxLANNetNs(netConf *NetConf) (netns.NsHandle, error) {
	// Get VxLAN netns if existing
	vxLANnetNs, err := netns.GetFromName(netConf.GetName())
	if err == nil {
		return vxLANnetNs, nil
	}

	// Create it otherwise
	return createVxLANNetNs(netConf)
}

func createVxLANNetNs(netConf *NetConf) (netns.NsHandle, error) {
	// Get master
	masterLink, err := netlink.LinkByName(netConf.Master)
	if err != nil {
		return netns.None(), err
	}
	masterIP, err := getVxLANIP(masterLink)
	if err != nil {
		return netns.None(), err
	}

	// Get current network namespace
	baseNs, err := netns.Get()
	if err != nil {
		return netns.None(), err
	}

	// Create network namespace
	vxlanNetNs, err := netns.NewNamed(netConf.GetName())
	if err != nil {
		return netns.None(), err
	}
	handle, err := netlink.NewHandleAt(vxlanNetNs)
	if err != nil {
		return netns.None(), err
	}

	// Move to base network namespace
	err = netns.Set(baseNs)
	if err != nil {
		return netns.None(), err
	}

	// Create Bridge
	bridge := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: bridgeIfName,
		},
	}
	err = handle.LinkAdd(bridge)
	if err != nil {
		return netns.None(), err
	}
	err = handle.LinkSetUp(bridge)
	if err != nil {
		return netns.None(), err
	}

	// Create VxLAN attach it to the bridge
	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: vxlanIfName,
		},
		VxlanId:      netConf.VNI,
		VtepDevIndex: masterLink.Attrs().Index,
		Group:        net.ParseIP(netConf.Group),
		SrcAddr:      masterIP,
		TTL:          5,
	}
	err = netlink.LinkAdd(vxlan)
	if err != nil {
		return netns.None(), fmt.Errorf("a %v", err)
	}
	err = netlink.LinkSetNsFd(vxlan, int(netlink.NsFd(vxlanNetNs)))
	if err != nil {
		return netns.None(), err
	}

	err = handle.LinkSetMaster(vxlan, bridge)
	if err != nil {
		return netns.None(), err
	}
	err = handle.LinkSetUp(vxlan)
	if err != nil {
		return netns.None(), err
	}

	return vxlanNetNs, nil
}

func getVxLANIP(master netlink.Link) (net.IP, error) {
	addresses, err := netlink.AddrList(master, netlink.FAMILY_ALL)
	if err != nil {
		return net.IP{}, err
	}
	for _, addr := range addresses {
		if !addr.IP.IsLinkLocalUnicast() &&
			!addr.IP.IsInterfaceLocalMulticast() {
			return addr.IP, nil
		}
	}
	return net.IP{}, errors.New("master has no IP")
}
