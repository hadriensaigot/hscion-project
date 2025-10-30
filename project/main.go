package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/path/fabridquery"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"

	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet/path"

	pth "github.com/scionproto/scion/pkg/slayers/path"

	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-scion/lib"
)

// The local IP address of your endhost.
// It matches the IP address of the SCION daemon you should use for this run.
var local string

// The remote SCION address of the verifier application.
var remote snet.UDPAddr

// The port of your SCION daemon.f
const daemonPort = 30255

func main() {
	// DO NOT MODIFY THIS FUNCTION
	err := log.Setup(log.Config{
		Console: log.ConsoleConfig{
			Level:           "DEBUG",
			StacktraceLevel: "none",
		},
	})
	if err != nil {
		fmt.Println(serrors.WrapStr("setting up logging", err))
	}
	flag.StringVar(&local, "local", "", "The local IP address which is the same IP as the IP of the local SCION daemon")
	flag.Var(&remote, "remote", "The address of the validator")
	flag.Parse()

	if err := realMain(); err != nil {
		log.Error("Error while running project", "err", err)
	}
}

var dec scion.Decoded
var MyHopFields []pth.HopField

func printDecodedPath(raw []byte) {

	if err := dec.DecodeFromBytes(raw); err != nil {
		fmt.Printf("Failed to decode path: %v\n", err)
		return
	}

	fmt.Println("Successfully decoded SCION path")

	for i, info := range dec.InfoFields {
		fmt.Printf("InfoField[%d]: ConsDir=%v, SegID=%x, Ts=%d\n",
			i, info.ConsDir, info.SegID, info.Timestamp)
	}

	MyHopFields = dec.HopFields
	for i, hop := range dec.HopFields {
		fmt.Printf("HopField[%d]: Ingress=%d → Egress=%d ExpTime=%d\n",
			i, hop.ConsIngress, hop.ConsEgress, hop.ExpTime)
	}
}

type DebugReplyPather struct {
	Base snet.ReplyPather
}

func (d DebugReplyPather) ReplyPath(rp snet.RawPath) (snet.DataplanePath, error) {
	printDecodedPath(rp.Raw)

	// Delegate to the underlying default builder
	dp, err := d.Base.ReplyPath(rp)
	if err != nil {
		fmt.Printf("Error building reply path: %v\n", err)
		return nil, err
	}
	return dp, nil
}

// matchReplyPath tries to identify which SCION path (from daemon) corresponds
// to the decoded HopFields (reply path from verifier), assuming reverse traversal.
// It prints and returns the ordered list of AS IAs.
func matchReplyPath(paths []snet.Path, hops []pth.HopField) []string {
	fmt.Println("\n=== Comparing decoded hopfields with known paths ===")

	if len(hops) == 0 {
		fmt.Println("No hopfields to compare.")
		return nil
	}

	bestMatchIdx := -1
	bestScore := -1

	for idx, p := range paths {
		md := p.Metadata()
		ifaces := md.Interfaces
		score := 0

		for i := 0; i < len(hops) && i < len(ifaces); i++ {
			hf := hops[i]
			iface := ifaces[len(ifaces)-1-i] // compare in reverse

			if uint16(iface.ID) == hf.ConsIngress || uint16(iface.ID) == hf.ConsEgress {
				score++
			}
		}

		fmt.Printf("→ Path #%d scored %d/%d matching hopfields.\n", idx, score, len(hops))

		if score > bestScore {
			bestScore = score
			bestMatchIdx = idx
		}
	}

	// Prepare output
	if bestMatchIdx < 0 {
		fmt.Println(" No matching path found for the decoded hopfields.")
		return nil
	}

	fmt.Printf("\nThe verifier's reply most likely corresponds to Path #%d (score=%d)\n", bestMatchIdx, bestScore)

	// Reverse traversal order (reply direction)
	md := paths[bestMatchIdx].Metadata()
	pathHops := md.Hops()
	reversedAS := make([]string, 0, len(pathHops))

	fmt.Println("Inferred AS traversal (reply path order):")
	for i := len(pathHops) - 1; i >= 0; i-- {
		fmt.Printf("  → %s (IngressIf=%d, EgressIf=%d)\n",
			pathHops[i].IA, pathHops[i].IgIf, pathHops[i].EgIf)
		reversedAS = append(reversedAS, pathHops[i].IA.String())
	}

	fmt.Printf("Ordered AS traversal list: %v\n", reversedAS)
	fmt.Println("============================================\n")

	return reversedAS
}

func realMain() error {
	ctx := context.Background()

	// 1. Connect to the local SCION daemon
	daemonAddr := fmt.Sprintf("%s:%d", local, daemonPort)

	sd, _ := daemon.NewService(daemonAddr).Connect(ctx)

	// 2. Get local ISD-AS
	localIA, _ := sd.LocalIA(ctx)

	// 3. Retrieve available paths from local to remote IA
	paths, _ := sd.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})

	// 4. Choose the first available path
	selectedPath := paths[0]

	// 5. Build the remote endpoint (set path and next hop)
	remoteEP := remote
	remoteEP.Path = selectedPath.Dataplane()
	remoteEP.NextHop = selectedPath.UnderlayNextHop()

	// 6. Create SCION network and dial verifier
	sn := snet.SCIONNetwork{Topology: sd}

	localEP, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))

	conn, _ := sn.Dial(ctx, "udp", localEP, &remoteEP)

	defer conn.Close()

	// 7. Build the JSON payload: {"ID":1,"Payload":{},"State":"TestRunning"}
	msg := lib.TestResult{
		ID:      1,
		Payload: "idk",
		State:   "TestRunning",
	}

	jsonBytes, _ := json.Marshal(msg)

	// 8. Send the JSON payload
	if _, err := conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	// 9. Read response (optional, but useful for debugging)
	buf := make([]byte, 2048)

	n, err := conn.Read(buf)

	if err == nil && n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	}

	sendWithPathInit := func(pathIndex int) (int, error) {
		// 4. Choose the first available path
		selectedPath := paths[pathIndex]

		// 5. Build the remote endpoint (set path and next hop)
		remoteEP := remote
		remoteEP.Path = selectedPath.Dataplane()
		remoteEP.NextHop = selectedPath.UnderlayNextHop()

		// 6. Create SCION network and dial verifier
		sn := snet.SCIONNetwork{Topology: sd}

		localEP, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))

		if err != nil {
			return 0, fmt.Errorf("resolving local UDP address: %w", err)
		}

		conn, err := sn.Dial(ctx, "udp", localEP, &remoteEP)

		if err != nil {
			return 0, fmt.Errorf("failed to dial verifier: %w", err)
		}

		defer conn.Close()

		// 7. Build the JSON payload: {"ID":1,"Payload":{},"State":"TestRunning"}
		msg := lib.TestResult{
			ID:      2,
			Payload: "idk",
			State:   "TestRunning",
		}

		jsonBytes, err := json.Marshal(msg)

		if err != nil {
			return 0, fmt.Errorf("failed to marshal JSON: %w", err)
		}

		// 8. Send the JSON payload
		if _, err := conn.Write(jsonBytes); err != nil {
			return 0, fmt.Errorf("failed to send payload: %w", err)
		}

		// 9. Read response (optional, but useful for debugging)
		buf := make([]byte, 2048)

		n, err := conn.Read(buf)

		if err != nil {
			return 0, fmt.Errorf("failed to send JSON: %w", err)
		}

		if err == nil && n > 0 {
			fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
		} else {
			fmt.Println("No response received from verifier (check topology/logs if needed)")
		}

		rcv := lib.TestResult{}

		err = json.Unmarshal(buf[:n], &rcv)

		if err != nil {
			return 0, fmt.Errorf("failed to send payload: %w", err)
		}

		// Payload is interface{} — check and convert to int
		payloadInt, ok := rcv.Payload.(float64) // JSON numbers become float64 by default

		if !ok {
			return 0, fmt.Errorf("failed to send payload: %w", err)
		}

		return int(payloadInt), nil
	}

	var val int // declare outside so it's visible everywhere

	val, _ = sendWithPathInit(0)

	for i := 1; i <= val; i++ {
		if _, err := sendWithPathInit(i); err == nil {
			fmt.Printf("Path %d succeeded \n", i)
		}
	}

	missingPerPath := []int{}

	for i, p := range paths {
		md := p.Metadata()

		// Count how many invalid (-1) CarbonIntensity values exist
		missing := 0
		for _, v := range md.CarbonIntensity {
			if v == -1 {
				missing++
			}
		}

		// Store this path's missing count
		missingPerPath = append(missingPerPath, missing)

		// Optional: print detailed info
		fmt.Printf("Path %d → CarbonIntensity: %v → Missing (invalid = -1): %d\n",
			i, md.CarbonIntensity, missing)
	}

	// 1️⃣ Find the minimum value
	minVal := missingPerPath[0]
	for _, v := range missingPerPath {
		if v < minVal {
			minVal = v
		}
	}

	// 2️⃣ Build the binary indicator array
	indicator := make([]int, len(missingPerPath))
	for i, v := range missingPerPath {
		if v == minVal {
			indicator[i] = 1
		} else {
			indicator[i] = 0
		}
	}

	// 3️⃣ Print results
	fmt.Println("MissingPerPath:", missingPerPath)
	fmt.Println("Min value:", minVal)
	fmt.Println("Indicator:", indicator)
	//smallestIdx is index of path to send over
	//find the min and check all indices with this value

	tmpsum := int64(10000) // initial large number
	bestIdx := -1          // to remember which path has the smallest sum

	for i, p := range paths {
		if indicator[i] != 1 {
			continue // skip paths not marked as valid
		}

		md := p.Metadata()

		// Compute the sum of CarbonIntensity for this path
		var sum int64 = 0
		for _, v := range md.CarbonIntensity {
			sum += v
		}

		fmt.Printf("Path %d → CarbonIntensity sum: %d\n", i, sum)

		// Update smallest sum and best index
		if sum < tmpsum {
			tmpsum = sum
			bestIdx = i
		}
	}

	fmt.Printf("\n✅ Smallest carbon intensity sum: %d (Path %d)\n", tmpsum, bestIdx)

	sendWithPathInit2 := func(pathIndex int) (int, error) {
		// 4. Choose the first available path
		selectedPath := paths[pathIndex]

		// 5. Build the remote endpoint (set path and next hop)
		remoteEP := remote
		remoteEP.Path = selectedPath.Dataplane()
		remoteEP.NextHop = selectedPath.UnderlayNextHop()

		// 6. Create SCION network and dial verifier
		sn := snet.SCIONNetwork{Topology: sd}

		localEP, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))

		conn, err := sn.Dial(ctx, "udp", localEP, &remoteEP)

		if err != nil {
			return 0, fmt.Errorf("failed to dial verifier: %w", err)
		}

		defer conn.Close()

		// 7. Build the JSON payload: {"ID":1,"Payload":{},"State":"TestRunning"}
		msg := lib.TestResult{
			ID:      10,
			Payload: "idk",
			State:   "TestRunning",
		}

		jsonBytes, err := json.Marshal(msg)

		// 8. Send the JSON payload
		if _, err := conn.Write(jsonBytes); err != nil {
			return 0, fmt.Errorf("failed to send payload: %w", err)
		}

		// 9. Read response (optional, but useful for debugging)
		buf := make([]byte, 2048)

		n, err := conn.Read(buf)

		if err == nil && n > 0 {
			fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
		}

		return 14, nil
	}
	_, _ = sendWithPathInit2(bestIdx)

	sendWithPathInit3 := func(pathIndex int) (int, error) {
		// 4. Choose the first available path
		selectedPath := paths[pathIndex]

		// 5. Build the remote endpoint (set path and next hop)
		remoteEP := remote
		remoteEP.Path = selectedPath.Dataplane()
		remoteEP.NextHop = selectedPath.UnderlayNextHop()

		// 6. Create SCION network and dial verifier
		sn := snet.SCIONNetwork{Topology: sd}

		localEP, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))

		if err != nil {
			return 0, fmt.Errorf("resolving local UDP address: %w", err)
		}

		conn, err := sn.Dial(ctx, "udp", localEP, &remoteEP)

		if err != nil {
			return 0, fmt.Errorf("failed to dial verifier: %w", err)
		}

		defer conn.Close()

		// 7. Build the JSON payload: {"ID":1,"Payload":{},"State":"TestRunning"}
		msg := lib.TestResult{
			ID:      11,
			Payload: "idk",
			State:   "TestRunning",
		}

		jsonBytes, _ := json.Marshal(msg)

		// 8. Send the JSON payload
		if _, err := conn.Write(jsonBytes); err != nil {
			return 0, fmt.Errorf("failed to send payload: %w", err)
		}

		// 9. Read response (optional, but useful for debugging)
		buf := make([]byte, 2048)

		n, err := conn.Read(buf)

		if err == nil && n > 0 {
			fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
		} else {
			fmt.Println("No response received from verifier (check topology/logs if needed)")
		}

		rcv := lib.TestResult{}

		err = json.Unmarshal(buf[:n], &rcv)

		// Payload is interface{} — check and convert to int
		payloadInt, ok := rcv.Payload.(float64) // JSON numbers become float64 by default

		if !ok {
			return 0, fmt.Errorf("failed to send payload: %w", err)
		}

		return int(payloadInt), nil
	}

	val, _ = sendWithPathInit3(1)

	zerosPerPathLatency := make([]int, len(paths))

	for i, p := range paths {
		md := p.Metadata()

		count := 0
		for _, l := range md.Latency {
			if l == -1 {
				count++
			}
		}
		zerosPerPathLatency[i] = count

		fmt.Printf("Path %d → Latencies: %v → Zero count: %d\n", i, md.Latency, count)
	}

	fmt.Println("\nZeros per path:", zerosPerPathLatency)

	zerosPerPathBandwidth := make([]int, len(paths))

	for i, p := range paths {
		md := p.Metadata()

		count := 0
		for _, bw := range md.Bandwidth {
			if bw == 0 {
				count++
			}
		}

		zerosPerPathBandwidth[i] = count

		fmt.Printf("Path %d → Bandwidth: %v → Zero count: %d\n",
			i, md.Bandwidth, count)
	}

	fmt.Println("\nZeros per path (bandwidth):", zerosPerPathBandwidth)

	validPaths := make([]int, len(zerosPerPathLatency))

	for i := range zerosPerPathLatency {
		if zerosPerPathLatency[i] == 0 && zerosPerPathBandwidth[i] == 0 {
			validPaths[i] = 1
		} else {
			validPaths[i] = 0
		}
	}

	fmt.Println("Valid paths (1 = complete data):", validPaths) //1 if valid, 0 if not valid

	latencySums := make([]int64, len(paths))

	for i, p := range paths {
		md := p.Metadata()
		// Compute sum of latencies for this path
		var totalLatency int64 = 0
		for _, l := range md.Latency {
			totalLatency += int64(l.Milliseconds()) // convert Duration to ms
		}

		latencySums[i] = totalLatency
	}

	fmt.Println("Latencies sum :", latencySums)

	bestIdx = -1
	maxBW := uint64(0)

	for i, p := range paths {
		md := p.Metadata()

		if validPaths[i] == 1 { //valid
			if latencySums[i] < int64(val) {
				// compute bottleneck bandwidth for this path
				minBW := uint64(md.Bandwidth[0])
				for _, bw := range md.Bandwidth {
					if uint64(bw) < minBW {
						minBW = uint64(bw)
					}
				}

				// update best path if this one is better
				if minBW > maxBW {
					maxBW = minBW
					bestIdx = i
				}
			}
		}
	}

	containsOne := func(arr []int) bool {
		for _, v := range arr {
			if v == 1 {
				return true
			}
		}
		return false
	}

	// no valid path here
	if !containsOne(validPaths) {
		candidateIndices := []int{}

		// 1️⃣ Find the smallest number of missing latency values
		minMissing := -1
		for _, missing := range zerosPerPathLatency {
			if minMissing == -1 || missing < minMissing {
				minMissing = missing
			}
		}

		// 2️⃣ Collect all paths that have this minimum missing count
		for j, missing := range zerosPerPathLatency {
			if missing == minMissing {
				candidateIndices = append(candidateIndices, j)
			}
		}

		fmt.Printf("Candidate paths (min latency zeros = %d): %v\n", minMissing, candidateIndices)

		// 3️⃣ Compute min bandwidth per path for candidates
		minBandPerPath := make([]uint64, len(paths))
		for _, j := range candidateIndices {
			md := paths[j].Metadata()
			if len(md.Bandwidth) > 0 {
				minBW := uint64(0)
				for _, bw := range md.Bandwidth {
					if bw == 0 {
						continue // skip missing data
					}
					if minBW == 0 || uint64(bw) < minBW {
						minBW = uint64(bw)
					}
				}
				minBandPerPath[j] = minBW
			} else {
				minBandPerPath[j] = 0 // no data at all
			}
		}
		fmt.Printf("Minimum bandwidth per path (candidates): %v\n", minBandPerPath)

		// 4️⃣ Find max(minBW) among these candidates
		maxBW := uint64(0)
		for _, j := range candidateIndices {
			if minBandPerPath[j] > maxBW {
				maxBW = minBandPerPath[j]
			}
		}
		fmt.Printf("Max bottleneck bandwidth among candidates: %d\n", maxBW)

		// 5️⃣ Mark all paths that have this maxBW
		bestBWFlags := make([]int, len(paths))
		for _, j := range candidateIndices {
			if minBandPerPath[j] == maxBW {
				bestBWFlags[j] = 1
			}
		}
		fmt.Printf("bestBWFlags: %v\n", bestBWFlags)

		// 6️⃣ Compute shortest path length among those
		minLen := -1
		for i, flag := range bestBWFlags {
			if flag == 1 {
				md := paths[i].Metadata()
				pathLen := len(md.Interfaces)
				if minLen == -1 || pathLen < minLen {
					minLen = pathLen
				}
			}
		}

		// Build shortestP array
		shortestP := make([]int, len(paths))
		for i, flag := range bestBWFlags {
			if flag == 1 {
				md := paths[i].Metadata()
				pathLen := len(md.Interfaces)
				if pathLen == minLen {
					shortestP[i] = 1
				}
			}
		}
		fmt.Printf("Shortest path length among maxBW paths: %d\n", minLen)
		fmt.Printf("shortestP: %v\n", shortestP)

		// 7️⃣ Among those, pick lexicographically smallest by interface IDs
		candidates := []int{}
		for i, flag := range shortestP {
			if flag == 1 {
				candidates = append(candidates, i)
			}
		}

		if len(candidates) == 0 {
			return fmt.Errorf("no candidate paths found")
		}

		// 8️⃣ If multiple candidates remain, sort them by length & interface IDs
		if len(candidates) > 1 {
			sort.Slice(candidates, func(a, b int) bool {
				mi := paths[candidates[a]].Metadata()
				mj := paths[candidates[b]].Metadata()

				// 1️⃣ Shorter path first
				if len(mi.Interfaces) != len(mj.Interfaces) {
					return len(mi.Interfaces) < len(mj.Interfaces)
				}

				// 2️⃣ Compare hop-by-hop lexicographically
				for k := 0; k < len(mi.Interfaces) && k < len(mj.Interfaces); k++ {
					iai := mi.Interfaces[k].IA.String()
					iaj := mj.Interfaces[k].IA.String()
					if iai != iaj {
						return iai < iaj
					}

					if mi.Interfaces[k].ID != mj.Interfaces[k].ID {
						return mi.Interfaces[k].ID < mj.Interfaces[k].ID
					}
				}

				// 3️⃣ All equal up to min length → shorter one wins
				return len(mi.Interfaces) < len(mj.Interfaces)
			})

			fmt.Printf("Multiple shortest paths; lexicographically sorted, choosing #%d\n", candidates[0])
			fmt.Println("Assuming missing bandwidth interfaces are not limiting (as per spec)")
		}

		// ✅ Final selected path index
		bestIdx = candidates[0]
	}

	//selectedPath := paths[bestIdx]
	fmt.Printf("Selected final path #%d\n", bestIdx)

	var err2 error

	_, err2 = sendWithPathInit3(bestIdx)
	if err2 == nil {
		fmt.Printf("Path %d succeeded \n", bestIdx)
	}

	// 🛰️ Print all interfaces per path for debugging
	fmt.Println("\nInterfaces per path:")
	for i, p := range paths {
		md := p.Metadata()

		fmt.Printf("Path %d → ", i)
		if len(md.Interfaces) == 0 {
			fmt.Println("(no interfaces)")
			continue
		}

		for k, intf := range md.Interfaces {
			fmt.Printf("[%d] %s#%d", k, intf.IA, intf.ID)
			if k < len(md.Interfaces)-1 {
				fmt.Print(" → ")
			}
		}
		fmt.Println()
	}

	isPathEPIC := func(p snet.Path) bool {
		md := p.Metadata()
		ep := md.EpicAuths

		// A path is EPIC if either authenticator is non-nil and non-empty
		return (len(ep.AuthPHVF) == 16 && len(ep.AuthLHVF) == 16)
	}

	for i, p := range paths {
		md := p.Metadata()
		pathLen := len(md.Interfaces)

		// Build a readable list of interfaces like: "1-ff00:0:110#1 -> 1-ff00:0:111#2"
		hops := ""
		for j, intf := range md.Interfaces {
			if j > 0 {
				hops += " → "
			}
			hops += fmt.Sprintf("%s#%d", intf.IA, intf.ID)
		}

		fmt.Printf("Path %d → Hidden (EPIC): %t | Length: %d hops | Interfaces: %s\n",
			i, isPathEPIC(p), pathLen, hops)
	}

	// 4️. Separate EPIC and normal paths
	var epicPaths, normalPaths []snet.Path
	for _, p := range paths {
		if isPathEPIC(p) {
			epicPaths = append(epicPaths, p)
		} else {
			normalPaths = append(normalPaths, p)
		}
	}

	// 5️. Choose which group to use
	var candidates []snet.Path
	if len(epicPaths) > 0 {
		candidates = epicPaths
		fmt.Println("Using hidden (EPIC) paths.")
	} else {
		candidates = normalPaths
		fmt.Println("No EPIC hidden paths available, using normal paths.")
	}

	// 6️. Sort by path length, then by interface IDs
	sort.Slice(candidates,
		func(i, j int) bool {
			mi := candidates[i].Metadata()
			mj := candidates[j].Metadata()
			if len(mi.Interfaces) != len(mj.Interfaces) {
				return len(mi.Interfaces) < len(mj.Interfaces)
			}
			for k := range mi.Interfaces {
				if k >= len(mj.Interfaces) {
					break
				}
				if mi.Interfaces[k].IA.String() != mj.Interfaces[k].IA.String() {
					return mi.Interfaces[k].IA.String() < mj.Interfaces[k].IA.String()
				}
				if mi.Interfaces[k].ID != mj.Interfaces[k].ID {
					return mi.Interfaces[k].ID < mj.Interfaces[k].ID
				}
			}
			return false
		})

	// 7️. Pick the best path (the first one in candidates after sorting)
	best := candidates[0]
	md := best.Metadata()

	fmt.Printf("\nSelected path → Hidden (EPIC): %t | Hops: %d\n", isPathEPIC(best), len(md.Interfaces))

	// 8️. Build the remote endpoint depending on whether the path is EPIC or normal
	var remoteDP snet.DataplanePath

	if isPathEPIC(best) {
		fmt.Println("Building EPIC dataplane for selected path...")

		scionPath, ok := best.Dataplane().(path.SCION)
		if !ok {
			return fmt.Errorf("EPIC path dataplane is not of type path.SCION — cannot build EPIC dataplane")
		}

		epicDP, err := path.NewEPICDataplanePath(scionPath, md.EpicAuths)
		if err != nil {
			return fmt.Errorf("failed to create EPIC dataplane: %w", err)
		}

		remoteDP = epicDP
	} else {
		fmt.Println("Using standard SCION dataplane for selected path...")
		remoteDP = best.Dataplane()
	}

	// 9. Build remote endpoint using the proper dataplane
	remoteEP = remote
	remoteEP.Path = remoteDP
	remoteEP.NextHop = best.UnderlayNextHop()

	fmt.Printf("remoteEP.Path type: %T\n", remoteDP)

	localEP, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))

	conn, _ = sn.Dial(ctx, "udp", localEP, &remoteEP)

	defer conn.Close()

	msg = lib.TestResult{
		ID:      20,
		Payload: "idk",
		State:   "TestRunning",
	}

	jsonBytes, err = json.Marshal(msg)

	if _, err := conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	buf = make([]byte, 2048)

	n, err = conn.Read(buf)

	if err == nil && n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	} else {
		fmt.Println("No response received from verifier (check topology/logs if needed)")
	}

	if err != nil {
		return fmt.Errorf("failed to connect to SCION daemon at %s: %w", daemonAddr, err)
	}

	// 2. Get local ISD-AS

	if err != nil {
		return fmt.Errorf("failed to get local IA: %w", err)
	}

	// 3. Retrieve available paths from local to remote IA
	paths, err = sd.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})
	if err != nil {
		return fmt.Errorf("failed to get paths: %w", err)
	}
	if len(paths) == 0 {
		return fmt.Errorf("no paths found to %s", remote.IA)
	}

	fmt.Println("\n=== ALL DISCOVERED PATHS AND THEIR FABRID POLICIES ===")
	for i, p := range paths {
		hops := p.Metadata().Hops()
		fmt.Printf("Path %d: (%d hops)\n", i, len(hops))

		for j, hop := range hops {
			fmt.Printf("  Hop %d: %s (IngressIf=%d → EgressIf=%d)\n",
				j, hop.IA, hop.IgIf, hop.EgIf)

			// FABRID capability check
			fmt.Printf("     FABRID enabled: %v\n", hop.FabridEnabled)

			if len(hop.Policies) == 0 {
				fmt.Println("     No advertised FABRID policies.")
				continue
			}

			fmt.Println("     Advertised FABRID policies:")
			for _, pol := range hop.Policies {
				fmt.Printf("       - Identifier: %v, Local: %v\n",
					pol.Identifier, pol.IsLocal)
			}
		}
		fmt.Println("------------------------------------------------------")
	}

	// 4. Choose a path
	selectedPath = paths[0]

	// Extract hop interfaces for FABRID query evaluation
	hops := selectedPath.Metadata().Hops()

	var (
		selectedHops      []snet.HopInterface
		selectedPolicyIDs []*fabrid.PolicyID
	)
	selectedHops = hops

	fmt.Println("==============================")
	fmt.Println("=============DEBUG FOR HOST SRC AND DEST=================")
	fmt.Printf("Local AS: %s\n", localIA)
	fmt.Printf("Local Host: %s\n", local)
	fmt.Printf("Remote AS : %d\n", remote.IA)
	fmt.Printf("Remote Host: %s\n", remote.Host)
	fmt.Printf("Remote Path : %d\n", remote.Path)
	fmt.Printf("Remote NextHop: %s\n", remote.NextHop)

	// --- 6) Parse and evaluate the FABRID query ---
	queryString := "{0-0#0,0@L1000 ? 0-0#0,0@L1000 : {0-0#0,0@L1001 ? 0-0#0,0@L1001 : {0-0#0,0@L1002 ? 0-0#0,0@L1002 : {0-0#0,0@L2000 ? 0-0#0,0@L2000 : 0-0#0,0@REJECT}}}}"

	// Example: require policy L1000 on all hops
	fq, err := fabridquery.ParseFabridQuery(queryString)
	if err != nil {
		return fmt.Errorf("invalid FABRID query: %w", err)
	}

	// Initialize MatchList to store results
	var ml fabridquery.MatchList
	ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

	// Evaluate query over hops
	matched, mlPtr := fq.Evaluate(hops, &ml)
	if !matched {
		return fmt.Errorf("FABRID query matched no policies")
	}

	// Extract matching policy IDs from the MatchList
	policyIDs := mlPtr.Policies()
	if len(policyIDs) == 0 {
		fmt.Printf("no FABRID policies selected for dataplane path")
	}
	selectedPolicyIDs = policyIDs

	scionDP, _ := selectedPath.Dataplane().(path.SCION)

	localEP, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
	remoteEP = remote
	remoteEP.NextHop = selectedPath.UnderlayNextHop()

	normalizeIPv6 := func(addr string) string {
		s := strings.TrimSpace(addr)
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			s = s[1 : len(s)-1]
		}
		return s
	}

	// --- Create the FABRID dataplane path ---
	conf := &path.FabridConfig{}

	fabridDP, err := path.NewFABRIDDataplanePath(
		scionDP,
		selectedHops,
		selectedPolicyIDs,
		conf,
		func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
			meta.SrcAS = localIA
			meta.DstAS = remote.IA

			// ✅ FIXED: clean IPv6 brackets
			meta.SrcHost = normalizeIPv6(local)

			// ✅ DstHost: keep clean too
			dst := remote.Host.IP.String()
			meta.DstHost = &dst

			fmt.Printf("=== DRKey Meta Debug ===\n")
			fmt.Printf("SrcAS: %s\n", meta.SrcAS)
			fmt.Printf("DstAS: %s\n", meta.DstAS)
			fmt.Printf("SrcHost: %s\n", meta.SrcHost)
			fmt.Printf("DstHost: %s\n", *meta.DstHost)
			fmt.Printf("PathASes: %v\n", meta.PathASes)
			fmt.Println("========================")
			return sd.FabridKeys(c, meta)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to build FABRID dataplane path: %w", err)
	}

	remoteEP.Path = fabridDP

	sn = snet.SCIONNetwork{Topology: sd}
	conn, err = sn.Dial(ctx, "udp", localEP, &remoteEP)

	if err != nil {
		return fmt.Errorf("failed to dial verifier using FABRID path: %w", err)
	}
	defer conn.Close()

	// --- 9) Build the JSON payload ---
	msg = lib.TestResult{
		ID:      30,
		Payload: false,
		State:   "TestRunning",
	}

	jsonBytes, err = json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if _, err = conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	buf = make([]byte, 2048)
	n, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	} else {
		fmt.Println("No response received from verifier.")
	}

	ctx = context.Background()

	// 1. Connect to the local SCION daemon
	daemonAddr = fmt.Sprintf("%s:%d", local, daemonPort)

	sd, err = daemon.NewService(daemonAddr).Connect(ctx)

	if err != nil {
		return fmt.Errorf("failed to connect to SCION daemon at %s: %w", daemonAddr, err)
	}

	// 2. Get local ISD-AS
	localIA, err = sd.LocalIA(ctx)

	if err != nil {
		return fmt.Errorf("failed to get local IA: %w", err)
	}

	paths, err = sd.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})

	if err != nil {
		return fmt.Errorf("failed to get paths: %w", err)
	}

	selectedPath = paths[0]

	// 3. Create SCION network and dial verifier
	sn = snet.SCIONNetwork{
		Topology:    sd,
		ReplyPather: DebugReplyPather{Base: snet.DefaultReplyPather{}},
	}

	localEP, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))

	if err != nil {
		return fmt.Errorf("resolving local UDP address: %w", err)
	}

	// 4. Build the remote endpoint (set path and next hop)
	remoteEP = remote
	remoteEP.Path = selectedPath.Dataplane()
	remoteEP.NextHop = selectedPath.UnderlayNextHop()

	conn, err = sn.Dial(ctx, "udp", localEP, &remoteEP)

	if err != nil {
		return fmt.Errorf("failed to dial verifier: %w", err)
	}

	defer conn.Close()

	// 5. Build the JSON payload: {"ID":1,"Payload":{},"State":"TestRunning"}
	msg = lib.TestResult{
		ID:      40,
		Payload: "",
		State:   "TestRunning",
	}

	jsonBytes, err = json.Marshal(msg)

	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// 6. Send the JSON payload
	if _, err = conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	// 7. Read response (optional, but useful for debugging)
	buf = make([]byte, 2048)

	n, err = conn.Read(buf)

	if err != nil {
		return fmt.Errorf("failed to send JSON: %w", err)
	}

	if err == nil && n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	} else {
		fmt.Println("No response received from verifier (check topology/logs if needed)")

	}

	for {
		// Build the list of traversed ASes based on decoded HopFields
		traversed := matchReplyPath(paths, MyHopFields)

		// Build JSON payload to send back
		msg := lib.TestResult{
			ID:      40,
			Payload: traversed,
			State:   "TestRunning",
		}

		jsonBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		// Send JSON payload to verifier
		if _, err := conn.Write(jsonBytes); err != nil {
			return fmt.Errorf("failed to send payload: %w", err)
		}

		fmt.Printf("Sent payload with inferred path: %v\n", traversed)

		// Wait for verifier's response
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read verifier response: %w", err)
		}

		if n == 0 {
			fmt.Println("⚠️ No response from verifier, retrying...")
			continue
		}

		// Decode verifier’s reply
		var reply lib.TestResult
		if err := json.Unmarshal(buf[:n], &reply); err != nil {
			return fmt.Errorf("failed to unmarshal verifier reply: %w", err)
		}

		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))

		// Check verifier state
		if strings.EqualFold(string(reply.State), "TestRunning") {
			fmt.Println("Verifier still running test, sending next update...")
			// Loop again — keep exchanging until state changes
			continue
		}

		// Exit condition: verifier reports Success or another final state
		fmt.Printf("Verifier finished with state: %s\n", reply.State)
		break
	}

	daemonAddr = fmt.Sprintf("%s:%d", local, daemonPort)
	sd, _ = daemon.NewService(daemonAddr).Connect(ctx)

	localIA, _ = sd.LocalIA(ctx)

	paths, _ = sd.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})

	// --- 6) Parse and evaluate the FABRID query ---
	queryString = "{ 0-0#0,0@L1000 ? 0-0#0,0@L1000 : { 0-0#0,0@L1001 ? 0-0#0,0@L1001 : 0-0#0,0@REJECT } }"

	type candidate struct {
		path snet.Path
		hops []snet.HopInterface
		pids []*fabrid.PolicyID
	}

	var matchedD []candidate

	fabridexist := false
	fmt.Println("=== %d===", fabridexist)
	var matchedPath []snet.Path

	for idx, p := range paths {

		selectedPath := p

		hops := selectedPath.Metadata().Hops()

		selectedHops = hops

		fq, _ := fabridquery.ParseFabridQuery(queryString)

		var ml fabridquery.MatchList
		ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

		matched, mlPtr := fq.Evaluate(hops, &ml)
		if !matched {
			fmt.Printf("  No match on path %d .\n", idx)
			continue
		}

		rejected := false

		for i, pol := range ml.SelectedPolicies {
			if pol == nil {
				fmt.Printf("  Hop %d has no matching policy -> reject\n", i)
				rejected = true
				break
			}
			if pol.Type == fabridquery.REJECT_POLICY_TYPE {
				fmt.Printf("  Hop %d explicitly rejected\n", i)
				rejected = true
				break
			}
		}

		if rejected {
			fmt.Printf("  → FABRID query rejected this path %d (missing or REJECT).\n", idx)
			continue
		}

		// Extract matching policy IDs from the MatchList
		policyIDs := mlPtr.Policies()
		if len(policyIDs) == 0 {
			fmt.Println("  → No FABRID policies selected for this path.")
			continue
		}

		if true {
			fmt.Printf("  → Path %d satisfies the FABRID query!\n", idx)
			pids := mlPtr.Policies()
			matchedD = append(matchedD, candidate{path: p, hops: hops, pids: pids})
			matchedPath = append(matchedPath, p)
			continue
		}
	}

	if len(matchedD) == 0 {
		fabridexist = false
		fmt.Printf("%d", fabridexist)
		fmt.Println("⚠️ No FABRID path matches the policy. Falling back to default.")
		// 4. Choose a path
		selectedPath := paths[0]

		// Extract hop interfaces for FABRID query evaluation
		hops := selectedPath.Metadata().Hops()
		selectedHops := hops
		queryString := "0-0#0,0@L1000"
		fq, err := fabridquery.ParseFabridQuery(queryString)
		if err != nil {
			return fmt.Errorf("invalid FABRID query: %w", err)
		}

		// Initialize MatchList to store results
		var ml fabridquery.MatchList
		ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

		// Evaluate query over hops
		matched, mlPtr := fq.Evaluate(hops, &ml)
		if !matched {
			return fmt.Errorf("FABRID query matched no policies")
		}

		// Extract matching policy IDs from the MatchList
		policyIDs := mlPtr.Policies()
		if len(policyIDs) == 0 {
			fmt.Printf("no FABRID policies selected for dataplane path")
		}
		selectedPolicyIDs = policyIDs

		scionDP, _ := selectedPath.Dataplane().(path.SCION)

		localEP, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
		remoteEP := remote
		remoteEP.NextHop = selectedPath.UnderlayNextHop()

		// --- Create the FABRID dataplane path ---
		conf := &path.FabridConfig{}

		fabridDP, err := path.NewFABRIDDataplanePath(
			scionDP,
			selectedHops,
			selectedPolicyIDs,
			conf,
			func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
				meta.SrcAS = localIA
				meta.DstAS = remote.IA

				// ✅ FIXED: clean IPv6 brackets
				meta.SrcHost = normalizeIPv6(local)

				// ✅ DstHost: keep clean too
				dst := remote.Host.IP.String()
				meta.DstHost = &dst

				fmt.Printf("=== DRKey Meta Debug ===\n")
				fmt.Printf("SrcAS: %s\n", meta.SrcAS)
				fmt.Printf("DstAS: %s\n", meta.DstAS)
				fmt.Printf("SrcHost: %s\n", meta.SrcHost)
				fmt.Printf("DstHost: %s\n", *meta.DstHost)
				fmt.Printf("PathASes: %v\n", meta.PathASes)
				fmt.Println("========================")
				return sd.FabridKeys(c, meta)
			},
		)
		if err != nil {
			return fmt.Errorf("failed to build FABRID dataplane path: %w", err)
		}

		remoteEP.Path = fabridDP

		sn := snet.SCIONNetwork{Topology: sd}
		conn, err := sn.Dial(ctx, "udp", localEP, &remoteEP)

		if err != nil {
			return fmt.Errorf("failed to dial verifier using FABRID path: %w", err)
		}
		defer conn.Close()

		// --- 9) Build the JSON payload ---
		msg := lib.TestResult{
			ID:      31,
			Payload: fabridexist,
			State:   "TestRunning",
		}

		jsonBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		if _, err := conn.Write(jsonBytes); err != nil {
			return fmt.Errorf("failed to send payload: %w", err)
		}

		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		if n > 0 {
			fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
		} else {
			fmt.Println("No response received from verifier.")
		}
		return nil
	}

	if len(matchedD) >= 1 {
		fabridexist = true
		fmt.Printf(" %d", fabridexist)
	}

	fmt.Printf("%d", fabridexist)

	sort.Slice(matchedPath, func(a, b int) bool {
		ma := matchedPath[a].Metadata()
		mb := matchedPath[b].Metadata()

		if len(ma.Interfaces) != len(mb.Interfaces) {
			return len(ma.Interfaces) < len(mb.Interfaces)
		}

		for k := 0; k < len(ma.Interfaces) && k < len(mb.Interfaces); k++ {
			iai := ma.Interfaces[k].IA.String()
			iaj := mb.Interfaces[k].IA.String()
			if iai != iaj {
				return iai < iaj
			}

			if ma.Interfaces[k].ID != mb.Interfaces[k].ID {
				return ma.Interfaces[k].ID < mb.Interfaces[k].ID
			}
		}
		return len(ma.Interfaces) < len(mb.Interfaces)
	})

	// --- DEBUG PRINT ---
	fmt.Println("=== SORTED MATCHED PATHS ===")
	for order, p := range matchedPath {
		hops := p.Metadata().Hops()
		fmt.Printf("Matched Path #%d - %d hops\n", order, len(hops))
		for i, hop := range hops {
			fmt.Printf("  Hop %d: %s (IngressIf=%d → EgressIf=%d)\n",
				i, hop.IA, hop.IgIf, hop.EgIf)

			if len(hop.Policies) == 0 {
				fmt.Println("     No advertised FABRID policies.")
				continue
			}

			fmt.Println("     Advertised FABRID policies:")
			for _, pol := range hop.Policies {
				fmt.Printf("       - Identifier: %v, Local: %v\n", pol.Identifier, pol.IsLocal)
			}
		}
		fmt.Println("------------------------------------------------------")
	}

	//SEND THE PACKET WITH THE BEST PATH
	best2 := matchedD[0]
	selectedPath = best2.path
	selectedHops = best2.hops
	selectedPolicyIDs = best2.pids
	scionDP, _ = selectedPath.Dataplane().(path.SCION)
	localEP, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
	remoteEP = remote
	remoteEP.NextHop = selectedPath.UnderlayNextHop()

	conf = &path.FabridConfig{}

	fabridDP, _ = path.NewFABRIDDataplanePath(
		scionDP,
		selectedHops,
		selectedPolicyIDs,
		conf,
		func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
			meta.SrcAS = localIA
			meta.DstAS = remote.IA

			// ✅ FIXED: clean IPv6 brackets
			meta.SrcHost = normalizeIPv6(local)

			// ✅ DstHost: keep clean too
			dst := remote.Host.IP.String()
			meta.DstHost = &dst

			fmt.Printf("=== DRKey Meta Debug ===\n")
			fmt.Printf("SrcAS: %s\n", meta.SrcAS)
			fmt.Printf("DstAS: %s\n", meta.DstAS)
			fmt.Printf("SrcHost: %s\n", meta.SrcHost)
			fmt.Printf("DstHost: %s\n", *meta.DstHost)
			fmt.Printf("PathASes: %v\n", meta.PathASes)
			fmt.Println("========================")
			return sd.FabridKeys(c, meta)
		},
	)

	remoteEP.Path = fabridDP
	sn = snet.SCIONNetwork{Topology: sd}
	conn, _ = sn.Dial(ctx, "udp", localEP, &remoteEP)

	defer conn.Close()

	msg = lib.TestResult{
		ID:      31,
		Payload: fabridexist,
		State:   "TestRunning",
	}

	jsonBytes, _ = json.Marshal(msg)

	if _, err = conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	buf = make([]byte, 2048)
	n, err = conn.Read(buf)

	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	}

	var matchedPath2 []snet.Path

	daemonAddr = fmt.Sprintf("%s:%d", local, daemonPort)
	sd, _ = daemon.NewService(daemonAddr).Connect(ctx)

	localIA, _ = sd.LocalIA(ctx)

	paths, _ = sd.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})

	// --- 6) Parse and evaluate the FABRID query ---
	queryString = "{0-0#0,0@L1000 ? 0-0#0,0@L1000 : {0-0#0,0@L1001 ? 0-0#0,0@L1001 : {0-0#0,0@L1002 ? 0-0#0,0@L1002 : {0-0#0,0@L2000 ? 0-0#0,0@L2000 : 0-0#0,0@REJECT}}}}"

	var matchedD2 []candidate

	fabridexist = false
	fmt.Println("=== %d===", fabridexist)

	for idx, p := range paths {

		selectedPath := p

		hops := selectedPath.Metadata().Hops()

		selectedHops = hops

		fq, _ := fabridquery.ParseFabridQuery(queryString)

		var ml fabridquery.MatchList
		ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

		matched, mlPtr := fq.Evaluate(hops, &ml)
		if !matched {
			fmt.Printf(" no match on path %d .\n", idx)
			continue
		}

		// Extract matching policy IDs from the MatchList
		policyIDs := mlPtr.Policies()
		if len(policyIDs) == 0 {
			fmt.Println("  → No FABRID policies selected for this path.")
			continue
		}

		if true {
			fmt.Printf("  → Path %d satisfies the FABRID query!\n", idx)
			pids := mlPtr.Policies()
			matchedD = append(matchedD, candidate{path: p, hops: hops, pids: pids})
			matchedPath = append(matchedPath, p)
			continue
		}
	}

	if len(matchedD) == 0 {
		fabridexist = false
		fmt.Printf("%d", fabridexist)
		fmt.Println("⚠️ No FABRID path matches the policy. Falling back to default.")
		// 4. Choose a path
		selectedPath := paths[0]

		// Extract hop interfaces for FABRID query evaluation
		hops := selectedPath.Metadata().Hops()
		selectedHops := hops
		queryString := "0-0#0,0@L1000"
		fq, err := fabridquery.ParseFabridQuery(queryString)
		if err != nil {
			return fmt.Errorf("invalid FABRID query: %w", err)
		}

		// Initialize MatchList to store results
		var ml fabridquery.MatchList
		ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

		// Evaluate query over hops
		matched, mlPtr := fq.Evaluate(hops, &ml)
		if !matched {
			return fmt.Errorf("FABRID query matched no policies")
		}

		// Extract matching policy IDs from the MatchList
		policyIDs := mlPtr.Policies()
		if len(policyIDs) == 0 {
			fmt.Printf("no FABRID policies selected for dataplane path")
		}
		selectedPolicyIDs = policyIDs

		scionDP, _ := selectedPath.Dataplane().(path.SCION)

		localEP, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
		remoteEP := remote
		remoteEP.NextHop = selectedPath.UnderlayNextHop()

		// --- Create the FABRID dataplane path ---
		conf := &path.FabridConfig{}

		fabridDP, err := path.NewFABRIDDataplanePath(
			scionDP,
			selectedHops,
			selectedPolicyIDs,
			conf,
			func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
				meta.SrcAS = localIA
				meta.DstAS = remote.IA

				// ✅ FIXED: clean IPv6 brackets
				meta.SrcHost = normalizeIPv6(local)

				// ✅ DstHost: keep clean too
				dst := remote.Host.IP.String()
				meta.DstHost = &dst

				fmt.Printf("=== DRKey Meta Debug ===\n")
				fmt.Printf("SrcAS: %s\n", meta.SrcAS)
				fmt.Printf("DstAS: %s\n", meta.DstAS)
				fmt.Printf("SrcHost: %s\n", meta.SrcHost)
				fmt.Printf("DstHost: %s\n", *meta.DstHost)
				fmt.Printf("PathASes: %v\n", meta.PathASes)
				fmt.Println("========================")
				return sd.FabridKeys(c, meta)
			},
		)
		if err != nil {
			return fmt.Errorf("failed to build FABRID dataplane path: %w", err)
		}

		remoteEP.Path = fabridDP

		sn := snet.SCIONNetwork{Topology: sd}
		conn, err := sn.Dial(ctx, "udp", localEP, &remoteEP)

		if err != nil {
			return fmt.Errorf("failed to dial verifier using FABRID path: %w", err)
		}
		defer conn.Close()

		// --- 9) Build the JSON payload ---
		msg := lib.TestResult{
			ID:      32,
			Payload: fabridexist,
			State:   "TestRunning",
		}

		jsonBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		if _, err := conn.Write(jsonBytes); err != nil {
			return fmt.Errorf("failed to send payload: %w", err)
		}

		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		if n > 0 {
			fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
		} else {
			fmt.Println("No response received from verifier.")
		}
		return nil
	}

	if len(matchedD) >= 1 {
		for _, cand := range matchedD {
			hops := cand.hops

			// Track whether we saw any hop in ISD 1 / ISD 2
			sawISD1 := false
			sawISD2 := false

			// ISD1: all hops must have L1000
			isd1AllL1000 := true

			// ISD2: either all L1001 or all L1002
			isd2AllL1001 := true
			isd2AllL1002 := true

			for i, hop := range hops {
				// Extract ISD number safely from IA string: "1-ff00:0:113" -> "1"
				iaStr := hop.IA.String()
				dash := strings.IndexByte(iaStr, '-')
				if dash < 0 {
					// If IA formatting is unexpected, reject this candidate
					fmt.Printf("Path rejected: hop %d has malformed IA: %q\n", i, iaStr)
					isd1AllL1000, isd2AllL1001, isd2AllL1002 = false, false, false
					break
				}
				isdStr := iaStr[:dash]

				// Helper: does this hop advertise a given local policy?
				has := func(id uint32) bool {
					for _, pol := range hop.Policies {
						if pol.Identifier == id {
							return true
						}
					}
					return false
				}

				switch isdStr {
				case "1":
					sawISD1 = true
					if !has(1000) {
						isd1AllL1000 = false
						// keep scanning to finish diagnostics, or break early if you prefer
					}
				case "2":
					sawISD2 = true
					// For ISD2, keep both possibilities alive until disproved
					if !has(1001) {
						isd2AllL1001 = false
					}
					if !has(1002) {
						isd2AllL1002 = false
					}
				default:
					// Other ISDs are unconstrained by this rule; ignore them
				}
			}

			// Apply the "if only one ISD is traversed, the other rule doesn't matter" clause
			isISD1OK := !sawISD1 || isd1AllL1000
			isISD2OK := !sawISD2 || (isd2AllL1001 || isd2AllL1002)

			if isISD1OK && isISD2OK {
				fabridexist = true
				fmt.Printf(" %d", fabridexist)
				matchedD2 = append(matchedD2, cand)
				matchedPath2 = append(matchedPath2, cand.path)
				fmt.Printf("Path accepted (ISD1 all L1000; ISD2 all L1001 or all L1002): %d hops\n", len(hops))
			} else {
				// Optional debugging
				if sawISD1 && !isd1AllL1000 {
					fmt.Println("Path rejected: ISD 1 does not have L1000 on all hops")
				}
				if sawISD2 && !(isd2AllL1001 || isd2AllL1002) {
					fmt.Println("Path rejected: ISD 2 is not uniformly L1001 or uniformly L1002")
				}
			}
		}
		// Debug summary
		fmt.Printf("=== Filtered paths (ISD1=L1000, ISD2=all L1001 OR all L1002): %d/%d ===\n", len(matchedD2), len(matchedD))
		for i, cand := range matchedD2 {
			hs := cand.hops
			firstIA := hs[0].IA
			lastIA := hs[len(hs)-1].IA
			fmt.Printf("  → Path #%d with %d hops (first=%s, last=%s)\n", i, len(hs), firstIA, lastIA)
		}
		fmt.Println("=============================================")

	}

	fmt.Printf("%d", fabridexist)

	sort.Slice(matchedPath2, func(a, b int) bool {
		ma := matchedPath2[a].Metadata()
		mb := matchedPath2[b].Metadata()

		if len(ma.Interfaces) != len(mb.Interfaces) {
			return len(ma.Interfaces) < len(mb.Interfaces)
		}

		for k := 0; k < len(ma.Interfaces) && k < len(mb.Interfaces); k++ {
			iai := ma.Interfaces[k].IA.String()
			iaj := mb.Interfaces[k].IA.String()
			if iai != iaj {
				return iai < iaj
			}

			if ma.Interfaces[k].ID != mb.Interfaces[k].ID {
				return ma.Interfaces[k].ID < mb.Interfaces[k].ID
			}
		}
		return len(ma.Interfaces) < len(mb.Interfaces)
	})

	// --- DEBUG PRINT ---
	fmt.Println("=== SORTED MATCHED PATHS ===")
	for order, p := range matchedPath2 {
		hops := p.Metadata().Hops()
		fmt.Printf("Matched Path #%d - %d hops\n", order, len(hops))
		for i, hop := range hops {
			fmt.Printf("  Hop %d: %s (IngressIf=%d → EgressIf=%d)\n",
				i, hop.IA, hop.IgIf, hop.EgIf)

			if len(hop.Policies) == 0 {
				fmt.Println("     No advertised FABRID policies.")
				continue
			}

			fmt.Println("     Advertised FABRID policies:")
			for _, pol := range hop.Policies {
				fmt.Printf("       - Identifier: %v, Local: %v\n", pol.Identifier, pol.IsLocal)
			}
		}
		fmt.Println("------------------------------------------------------")
	}

	//SEND THE PACKET WITH THE BEST PATH
	best3 := matchedD2[0]
	selectedPath = best3.path
	selectedHops = best3.hops
	selectedPolicyIDs = best3.pids
	scionDP, _ = selectedPath.Dataplane().(path.SCION)
	localEP, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
	remoteEP = remote
	remoteEP.NextHop = selectedPath.UnderlayNextHop()

	conf = &path.FabridConfig{}

	fabridDP, _ = path.NewFABRIDDataplanePath(
		scionDP,
		selectedHops,
		selectedPolicyIDs,
		conf,
		func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
			meta.SrcAS = localIA
			meta.DstAS = remote.IA

			// ✅ FIXED: clean IPv6 brackets
			meta.SrcHost = normalizeIPv6(local)

			// ✅ DstHost: keep clean too
			dst := remote.Host.IP.String()
			meta.DstHost = &dst

			fmt.Printf("=== DRKey Meta Debug ===\n")
			fmt.Printf("SrcAS: %s\n", meta.SrcAS)
			fmt.Printf("DstAS: %s\n", meta.DstAS)
			fmt.Printf("SrcHost: %s\n", meta.SrcHost)
			fmt.Printf("DstHost: %s\n", *meta.DstHost)
			fmt.Printf("PathASes: %v\n", meta.PathASes)
			fmt.Println("========================")
			return sd.FabridKeys(c, meta)
		},
	)

	remoteEP.Path = fabridDP
	sn = snet.SCIONNetwork{Topology: sd}
	conn, _ = sn.Dial(ctx, "udp", localEP, &remoteEP)

	defer conn.Close()

	msg = lib.TestResult{
		ID:      32,
		Payload: fabridexist,
		State:   "TestRunning",
	}

	jsonBytes, _ = json.Marshal(msg)

	if _, err = conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	buf = make([]byte, 2048)
	n, err = conn.Read(buf)

	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	}

	// --- 6) Parse and evaluate the FABRID query ---
	queryString = "{0-0#0,0@L1000 ? 0-0#0,0@L1000 : {0-0#0,0@L1001 ? 0-0#0,0@L1001 : {0-0#0,0@L1002 ? 0-0#0,0@L1002 : {0-0#0,0@L2000 ? 0-0#0,0@L2000 : 0-0#0,0@REJECT}}}}"

	fabridexist = false
	fmt.Println("=== %d===", fabridexist)

	for idx, p := range paths {

		selectedPath := p

		hops := selectedPath.Metadata().Hops()

		selectedHops = hops

		fq, _ := fabridquery.ParseFabridQuery(queryString)

		var ml fabridquery.MatchList
		ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

		matched, mlPtr := fq.Evaluate(hops, &ml)
		if !matched {
			fmt.Printf(" no match on path %d .\n", idx)
			continue
		}

		// Extract matching policy IDs from the MatchList
		policyIDs := mlPtr.Policies()
		if len(policyIDs) == 0 {
			fmt.Println("  → No FABRID policies selected for this path.")
			continue
		}

		if true {
			fmt.Printf("  → Path %d satisfies the FABRID query!\n", idx)
			pids := mlPtr.Policies()
			matchedD = append(matchedD, candidate{path: p, hops: hops, pids: pids})
			matchedPath = append(matchedPath, p)
			continue
		}
	}

	// Evaluate query over hops
	var matchedD3 []candidate
	var matchedPath3 []snet.Path

	if len(matchedD) == 0 {
		fabridexist = false
		fmt.Printf("%d", fabridexist)
		fmt.Println("⚠️ No FABRID path matches the policy. Falling back to default.")
		// 4. Choose a path
		selectedPath := paths[0]

		// Extract hop interfaces for FABRID query evaluation
		hops := selectedPath.Metadata().Hops()
		selectedHops := hops
		queryString := "0-0#0,0@L1000"
		fq, err := fabridquery.ParseFabridQuery(queryString)
		if err != nil {
			return fmt.Errorf("invalid FABRID query: %w", err)
		}

		// Initialize MatchList to store results
		var ml fabridquery.MatchList
		ml.SelectedPolicies = make([]*fabridquery.Policy, len(hops))

		matched, mlPtr := fq.Evaluate(hops, &ml)
		if !matched {
			return fmt.Errorf("FABRID query matched no policies")
		}

		// Extract matching policy IDs from the MatchList
		policyIDs := mlPtr.Policies()
		if len(policyIDs) == 0 {
			fmt.Printf("no FABRID policies selected for dataplane path")
		}
		selectedPolicyIDs = policyIDs

		scionDP, _ = selectedPath.Dataplane().(path.SCION)

		localEP, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
		remoteEP = remote
		remoteEP.NextHop = selectedPath.UnderlayNextHop()

		// --- Create the FABRID dataplane path ---
		conf = &path.FabridConfig{}

		fabridDP, err = path.NewFABRIDDataplanePath(
			scionDP,
			selectedHops,
			selectedPolicyIDs,
			conf,
			func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
				meta.SrcAS = localIA
				meta.DstAS = remote.IA

				// ✅ FIXED: clean IPv6 brackets
				meta.SrcHost = normalizeIPv6(local)

				// ✅ DstHost: keep clean too
				dst := remote.Host.IP.String()
				meta.DstHost = &dst

				fmt.Printf("=== DRKey Meta Debug ===\n")
				fmt.Printf("SrcAS: %s\n", meta.SrcAS)
				fmt.Printf("DstAS: %s\n", meta.DstAS)
				fmt.Printf("SrcHost: %s\n", meta.SrcHost)
				fmt.Printf("DstHost: %s\n", *meta.DstHost)
				fmt.Printf("PathASes: %v\n", meta.PathASes)
				fmt.Println("========================")
				return sd.FabridKeys(c, meta)
			},
		)
		if err != nil {
			return fmt.Errorf("failed to build FABRID dataplane path: %w", err)
		}

		remoteEP.Path = fabridDP

		sn = snet.SCIONNetwork{Topology: sd}
		conn, err = sn.Dial(ctx, "udp", localEP, &remoteEP)

		if err != nil {
			return fmt.Errorf("failed to dial verifier using FABRID path: %w", err)
		}
		defer conn.Close()

		// --- 9) Build the JSON payload ---
		msg := lib.TestResult{
			ID:      33,
			Payload: fabridexist,
			State:   "TestRunning",
		}

		jsonBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		if _, err := conn.Write(jsonBytes); err != nil {
			return fmt.Errorf("failed to send payload: %w", err)
		}

		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		if n > 0 {
			fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
		} else {
			fmt.Println("No response received from verifier.")
		}
		return nil
	}

	if len(matchedD) >= 1 {
		fabridexist = true
		fmt.Printf(" %d", fabridexist)

		for _, cand := range matchedD {
			hops := cand.hops
			if len(hops) < 2 {
				// If there's no penultimate hop (e.g., 1-hop path), skip it
				continue
			}

			penultimate := hops[len(hops)-2]
			hasPenultimateL2000 := false

			// --- Check penultimate hop ---
			for _, pol := range penultimate.Policies {
				if pol.Identifier == 2000 {
					hasPenultimateL2000 = true
					break
				}
			}

			if !hasPenultimateL2000 {
				fmt.Printf("Path rejected: penultimate hop (%s) missing L2000\n", penultimate.IA)
				continue
			}

			// --- Check all other hops ---
			valid := true
			for i, hop := range hops {
				if i == len(hops)-2 {
					continue // already checked penultimate hop
				}

				hasL2000 := false
				hasL1002 := false

				for _, pol := range hop.Policies {
					if pol.Identifier == 2000 {
						hasL2000 = true
					}
					if pol.Identifier == 1002 {
						hasL1002 = true
					}
				}

				if !hasL2000 && !hasL1002 {
					fmt.Printf("Path rejected: hop %d (%s) missing both L2000 and L1002\n", i, hop.IA)
					valid = false
					break
				}
			}

			if valid {
				fabridexist = true
				matchedD3 = append(matchedD3, cand)
				matchedPath3 = append(matchedPath3, cand.path)
				fmt.Printf("Path accepted: penultimate has L2000, and all other hops have L2000 or L1002 (%d hops)\n", len(hops))
			}
		}

		// Debug summary
		for i, cand := range matchedD3 {
			fmt.Printf("  → Path #%d with %d hops (penultimate=%s)\n", i, len(cand.hops), cand.hops[len(cand.hops)-2].IA)
		}
		fmt.Println("=============================================")
	}

	fmt.Printf("%d", fabridexist)

	sort.Slice(matchedPath3, func(a, b int) bool {
		ma := matchedPath3[a].Metadata()
		mb := matchedPath3[b].Metadata()

		if len(ma.Interfaces) != len(mb.Interfaces) {
			return len(ma.Interfaces) < len(mb.Interfaces)
		}

		for k := 0; k < len(ma.Interfaces) && k < len(mb.Interfaces); k++ {
			iai := ma.Interfaces[k].IA.String()
			iaj := mb.Interfaces[k].IA.String()
			if iai != iaj {
				return iai < iaj
			}

			if ma.Interfaces[k].ID != mb.Interfaces[k].ID {
				return ma.Interfaces[k].ID < mb.Interfaces[k].ID
			}
		}
		return len(ma.Interfaces) < len(mb.Interfaces)
	})

	// --- DEBUG PRINT ---
	fmt.Println("=== SORTED MATCHED PATHS ===")
	for order, p := range matchedPath3 {
		hops := p.Metadata().Hops()
		fmt.Printf("Matched Path #%d - %d hops\n", order, len(hops))
		for i, hop := range hops {
			fmt.Printf("  Hop %d: %s (IngressIf=%d → EgressIf=%d)\n",
				i, hop.IA, hop.IgIf, hop.EgIf)

			if len(hop.Policies) == 0 {
				fmt.Println("     No advertised FABRID policies.")
				continue
			}

			fmt.Println("     Advertised FABRID policies:")
			for _, pol := range hop.Policies {
				fmt.Printf("       - Identifier: %v, Local: %v\n", pol.Identifier, pol.IsLocal)
			}
		}
		fmt.Println("------------------------------------------------------")
	}

	//SEND THE PACKET WITH THE BEST PATH
	best4 := matchedD3[0]
	selectedPath = best4.path
	selectedHops = best4.hops
	selectedPolicyIDs = best4.pids
	scionDP, _ = selectedPath.Dataplane().(path.SCION)
	localEP, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", local))
	remoteEP = remote
	remoteEP.NextHop = selectedPath.UnderlayNextHop()

	conf = &path.FabridConfig{}

	fabridDP, _ = path.NewFABRIDDataplanePath(
		scionDP,
		selectedHops,
		selectedPolicyIDs,
		conf,
		func(c context.Context, meta drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error) {
			meta.SrcAS = localIA
			meta.DstAS = remote.IA

			// ✅ FIXED: clean IPv6 brackets
			meta.SrcHost = normalizeIPv6(local)

			// ✅ DstHost: keep clean too
			dst := remote.Host.IP.String()
			meta.DstHost = &dst

			fmt.Printf("=== DRKey Meta Debug ===\n")
			fmt.Printf("SrcAS: %s\n", meta.SrcAS)
			fmt.Printf("DstAS: %s\n", meta.DstAS)
			fmt.Printf("SrcHost: %s\n", meta.SrcHost)
			fmt.Printf("DstHost: %s\n", *meta.DstHost)
			fmt.Printf("PathASes: %v\n", meta.PathASes)
			fmt.Println("========================")
			return sd.FabridKeys(c, meta)
		},
	)

	remoteEP.Path = fabridDP
	sn = snet.SCIONNetwork{Topology: sd}
	conn, _ = sn.Dial(ctx, "udp", localEP, &remoteEP)

	defer conn.Close()

	msg = lib.TestResult{
		ID:      33,
		Payload: fabridexist,
		State:   "TestRunning",
	}

	jsonBytes, _ = json.Marshal(msg)

	if _, err := conn.Write(jsonBytes); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	buf = make([]byte, 2048)
	n, err = conn.Read(buf)

	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if n > 0 {
		fmt.Printf("Verifier replied: %s\n", string(buf[:n]))
	}

	return nil
}
