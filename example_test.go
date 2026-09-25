package orbitdb_test

import (
	"context"
	"fmt"
	"os"
	"time"

	orbitdb "github.com/orbitdb/go-orbitdb"
	"github.com/orbitdb/go-orbitdb/accesscontrollers"
	"github.com/orbitdb/go-orbitdb/ipfs"
)

// Two peers replicate a keyvalue database. The second one only needs the
// address; everything else comes from the first over the network.
func Example() {
	ctx := context.Background()
	newPeer := func() (*ipfs.Node, *orbitdb.OrbitDB, func()) {
		dir, _ := os.MkdirTemp("", "orbitdb-example")
		node, err := ipfs.New(ctx, ipfs.Options{})
		if err != nil {
			panic(err)
		}
		odb, err := orbitdb.New(ctx, orbitdb.Options{IPFS: node, Directory: dir})
		if err != nil {
			panic(err)
		}
		return node, odb, func() {
			_ = odb.Stop()
			_ = node.Close()
			_ = os.RemoveAll(dir)
		}
	}
	nodeA, alice, closeA := newPeer()
	defer closeA()
	nodeB, bob, closeB := newPeer()
	defer closeB()
	if err := nodeB.Connect(ctx, nodeA.AddrInfo()); err != nil {
		panic(err)
	}

	// Alice creates a database anyone may write to.
	settings, err := alice.OpenKeyValue(ctx, "settings",
		orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{"*"}})))
	if err != nil {
		panic(err)
	}
	if _, err := settings.Put(ctx, "theme", "dark"); err != nil {
		panic(err)
	}

	// Bob opens it by address and waits for the value to arrive.
	replica, err := bob.OpenKeyValue(ctx, settings.Address())
	if err != nil {
		panic(err)
	}
	for range 100 {
		if v, err := replica.Get(ctx, "theme"); err == nil {
			fmt.Println("bob sees theme =", v)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Output: bob sees theme = dark
}
