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
	"fmt"
	"net"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// https://pkg.go.dev/github.com/google/nftables
// nft add table inet meridio-egress-vip-nat
// nft add chain inet meridio-egress-vip-nat conduit-a-nat { type nat hook postrouting priority 100\; }
// nft --debug all add rule inet meridio-egress-vip-nat conduit-a-nat ip saddr { 20.0.0.1/32 } ip protocol tcp snat ip to 20.0.0.1:3000-4000

type NetConf struct {
	types.NetConf
	TableName            string `json:"table-name"`
	Vip                  string `json:"vip"`
	StartSourcePortRange uint   `json:"start-source-port-range"`
	EndSourcePortRange   uint   `json:"end-source-port-range"`
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

	err = netns.Do(func(_ ns.NetNS) error {
		table, err := getTable(n.TableName)
		if err != nil {
			return err
		}
		err = createRule(table, n.Vip, n.StartSourcePortRange, n.EndSourcePortRange)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	result := &current.Result{
		CNIVersion: n.CNIVersion,
		Interfaces: []*current.Interface{
			{
				Name:    args.IfName,
				Mac:     "00:00:00:00:00:00",
				Sandbox: args.Netns,
			},
		},
	}

	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// n, _, err := loadConf(args)
	// if err != nil {
	// 	return err
	// }

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		return nil
	})
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("loopback-vip"))
}

func loadConf(args *skel.CmdArgs) (*NetConf, string, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(args.StdinData, conf); err != nil {
		return conf, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return conf, conf.CNIVersion, nil
}

func createRule(table *nftables.Table, vip string, startSourcePortRange uint, endSourcePortRange uint) error {
	conn := &nftables.Conn{}
	chain := conn.AddChain(&nftables.Chain{
		Name:     fmt.Sprintf("%s-%d-%d", vip, startSourcePortRange, endSourcePortRange),
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityFilter,
	})
	parsedIP := net.ParseIP(vip)
	srcIp := parsedIP.To4()
	var family uint32 = unix.NFPROTO_IPV4
	if srcIp == nil {
		family = unix.NFPROTO_IPV6
		srcIp = parsedIP.To16()
	}
	// nft --debug all add rule inet meridio-egress-vip-nat conduit-a-nat ip saddr { 20.0.0.1/32 } ip protocol tcp snat ip to 20.0.0.1:3000-4000
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// 	[ meta load nfproto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			// 	[ cmp eq reg 1 0x00000002 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.AF_INET},
			},
			// 	[ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			// 	[ cmp eq reg 1 0x01000014 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     srcIp,
			},
			// 	[ payload load 1b @ network header + 9 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			// 	[ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// 	[ immediate reg 1 0x01000014 ]
			&expr.Immediate{
				Register: 1,
				Data:     srcIp,
			},
			// 	[ immediate reg 2 0x0000b80b ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(3000),
			},
			// 	[ immediate reg 3 0x0000a00f ]
			&expr.Immediate{
				Register: 3,
				Data:     binaryutil.BigEndian.PutUint16(4000),
			},
			// 	[ nat snat ip addr_min reg 1 proto_min reg 2 proto_max reg 3 flags 0x2 ]
			&expr.NAT{
				Type:        expr.NATTypeSourceNAT,
				Family:      family,
				RegAddrMin:  1,
				RegProtoMin: 2,
				RegProtoMax: 3,
			},
		},
	}
	_ = conn.AddRule(rule)
	return conn.Flush()
}

func getTable(tableName string) (*nftables.Table, error) {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("nftables list tables: %v", err)
	}
	for _, table := range tables {
		if table.Name == tableName {
			return table, nil
		}
	}
	return createTable(tableName)
}

func createTable(tableName string) (*nftables.Table, error) {
	conn := &nftables.Conn{}

	table := conn.AddTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	})

	err := conn.Flush()
	if err != nil {
		return nil, fmt.Errorf("nftables add table: %v", err)
	}
	return table, nil
}
