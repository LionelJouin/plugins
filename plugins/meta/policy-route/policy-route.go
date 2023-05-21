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
	"github.com/vishvananda/netlink"
)

type NetConf struct {
	types.NetConf
	Gateways     []string      `json:"gateways"`
	TableId      int           `json:"tableId"`
	PolicyRoutes []PolicyRoute `json:"policyRoutes"`
}

type PolicyRoute struct {
	SrcPrefix string `json:"src-prefix"`
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

	nexthopsV4, nexthopsV6 := getNextHops(n.Gateways)

	netns.Do(func(_ ns.NetNS) error {
		err = flushRoutingPolicies(n.TableId)
		if err != nil {
			return err
		}
		err = flushRoutingTables(n.TableId)
		if err != nil {
			return err
		}
		routeV4 := &netlink.Route{
			Table:     n.TableId,
			MultiPath: nexthopsV4,
		}
		routeV6 := &netlink.Route{
			Table:     n.TableId,
			MultiPath: nexthopsV6,
		}
		err := netlink.RouteAdd(routeV4)
		if err != nil {
			return err
		}
		err = netlink.RouteAdd(routeV6)
		if err != nil {
			return err
		}
		for _, policyRoute := range n.PolicyRoutes {
			_, SrcPrefix, err := net.ParseCIDR(policyRoute.SrcPrefix)
			if err != nil {
				continue
			}
			rule := netlink.NewRule()
			rule.Table = n.TableId
			rule.Src = &net.IPNet{
				IP:   SrcPrefix.IP,
				Mask: SrcPrefix.Mask,
			}
			if SrcPrefix.IP.To4() == nil {
				rule.Family = netlink.FAMILY_V6
			} else {
				rule.Family = netlink.FAMILY_V4
			}
			err = netlink.RuleAdd(rule)
			if err != nil {
				return err
			}
		}
		return nil
	})

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
	n, _, err := loadConf(args)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		err = flushRoutingPolicies(n.TableId)
		if err != nil {
			return err
		}
		return flushRoutingTables(n.TableId)
	})
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("policy-route"))
}

func loadConf(args *skel.CmdArgs) (*NetConf, string, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(args.StdinData, conf); err != nil {
		return conf, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return conf, conf.CNIVersion, nil
}

func getNextHops(gateways []string) ([]*netlink.NexthopInfo, []*netlink.NexthopInfo) {
	nexthopsV4 := []*netlink.NexthopInfo{}
	nexthopsV6 := []*netlink.NexthopInfo{}
	for _, gateway := range gateways {
		nexthop := net.ParseIP(gateway)
		if len(nexthop) == 0 {
			continue
		}
		if nexthop.To4() == nil {
			nexthopsV6 = append(nexthopsV6, &netlink.NexthopInfo{
				Gw: nexthop,
			})
			continue
		}
		nexthopsV4 = append(nexthopsV4, &netlink.NexthopInfo{
			Gw: nexthop,
		})
	}
	return nexthopsV4, nexthopsV6
}

func flushRoutingPolicies(tableId int) error {
	rules, err := netlink.RuleListFiltered(netlink.FAMILY_ALL, &netlink.Rule{
		Table: tableId,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		err = netlink.RuleDel(&rule)
		if err != nil {
			return err
		}
	}
	return nil
}

func flushRoutingTables(tableId int) error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
		Table: tableId,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range routes {
		err = netlink.RouteDel(&route)
		if err != nil {
			return err
		}
	}
	return nil
}
