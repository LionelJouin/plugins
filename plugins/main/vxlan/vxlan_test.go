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
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	types040 "github.com/containernetworking/cni/pkg/types/040"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

const (
	MASTER_NAME             = "eth0"
	MASTER_NAME_INCONTAINER = "eth1"
)

type tester interface {
	// verifyResult minimally verifies the Result and returns the interface's MAC address
	verifyResult(result types.Result, name string) string
}

type testerBase struct{}

type (
	testerV10x      testerBase
	testerV04x      testerBase
	testerV03x      testerBase
	testerV01xOr02x testerBase
)

func newTesterByVersion(version string) tester {
	switch {
	case strings.HasPrefix(version, "1.0."):
		return &testerV10x{}
	case strings.HasPrefix(version, "0.4."):
		return &testerV04x{}
	case strings.HasPrefix(version, "0.3."):
		return &testerV03x{}
	default:
		return &testerV01xOr02x{}
	}
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV10x) verifyResult(result types.Result, name string) string {
	r, err := types100.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(1))

	return r.Interfaces[0].Mac
}

func verify0403(result types.Result, name string) string {
	r, err := types040.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.Interfaces).To(HaveLen(1))
	Expect(r.Interfaces[0].Name).To(Equal(name))
	Expect(r.IPs).To(HaveLen(1))

	return r.Interfaces[0].Mac
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV04x) verifyResult(result types.Result, name string) string {
	return verify0403(result, name)
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV03x) verifyResult(result types.Result, name string) string {
	return verify0403(result, name)
}

// verifyResult minimally verifies the Result and returns the interface's MAC address
func (t *testerV01xOr02x) verifyResult(result types.Result, _ string) string {
	r, err := types020.GetResult(result)
	Expect(err).NotTo(HaveOccurred())

	Expect(r.IP4.IP.IP).NotTo(BeNil())
	Expect(r.IP6).To(BeNil())

	// 0.2 and earlier don't return MAC address
	return ""
}

var _ = Describe("vxlan Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dataDir string

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		dataDir, err = os.MkdirTemp("", "vxlan_test")
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// Add master
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: MASTER_NAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			m, err := netlink.LinkByName(MASTER_NAME)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(m)
			Expect(err).NotTo(HaveOccurred())
			addr, _ := netlink.ParseAddr("172.168.1.1/24")
			netlink.AddrAdd(m, addr)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// Add master
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: MASTER_NAME_INCONTAINER,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			m, err := netlink.LinkByName(MASTER_NAME_INCONTAINER)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(m)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
		Expect(originalNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNS)).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNS)).To(Succeed())
	})

	ver := "1.0.0"

	It(fmt.Sprintf("[%s] configures and deconfigures a vxlan link with ADD/CHECK/DEL", "v1.0.0"), func() {
		const IFNAME = "ethX"

		conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "vxlan1",
				"type": "vxlan",
				"master": "%s",
				"vni": %d,
				"group": "%s",
			    "ipam": {
				"type": "host-local",
				"subnet": "10.1.2.0/24",
				"dataDir": "%s"
			    }
			}`, ver, MASTER_NAME, 1234, "239.1.1.1", dataDir)

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData:   []byte(conf),
		}

		t := newTesterByVersion(ver)

		var result types.Result
		var macAddress string
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			var err error
			result, _, err = testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			macAddress = t.verifyResult(result, IFNAME)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure vlan link exists in the target namespace
		err = targetNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(IFNAME))

			if macAddress != "" {
				hwaddr, err := net.ParseMAC(macAddress)
				Expect(err).NotTo(HaveOccurred())
				Expect(link.Attrs().HardwareAddr).To(Equal(hwaddr))
			}

			addrs, err := netlink.AddrList(link, syscall.AF_INET)
			Expect(err).NotTo(HaveOccurred())
			Expect(addrs).To(HaveLen(1))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

	})
})
