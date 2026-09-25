// Command orbitdb-demo is a small interactive OrbitDB peer. Run one to
// create a database, then run a second one with --peer and --db set to what
// the first printed, and watch writes replicate both ways.
//
//	go run ./cmd/orbitdb-demo --dir /tmp/a
//	go run ./cmd/orbitdb-demo --dir /tmp/b --peer <multiaddr> --db <address>
//
// The databases are interoperable with @orbitdb/core 4, so the second peer
// can just as well be a JavaScript one.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	orbitdb "github.com/amirradjou/go-orbitdb"
	"github.com/amirradjou/go-orbitdb/accesscontrollers"
	"github.com/amirradjou/go-orbitdb/databases"
	"github.com/amirradjou/go-orbitdb/ipfs"
)

func main() {
	var (
		dir    = flag.String("dir", "./orbitdb-demo", "directory for keys, blocks and database state")
		listen = flag.String("listen", "/ip4/0.0.0.0/tcp/0", "libp2p listen address")
		peerMA = flag.String("peer", "", "multiaddr of a peer to connect to")
		dbName = flag.String("db", "demo", "database name to create, or address to open")
		dbType = flag.String("type", "keyvalue", "database type when creating: keyvalue, events or documents")
		anyone = flag.Bool("anyone", true, "when creating, let any peer write")
	)
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, *dir, *listen, *peerMA, *dbName, *dbType, *anyone, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir, listen, peerAddr, dbName, dbType string, anyone bool, in io.Reader, out io.Writer) error {
	node, err := ipfs.New(ctx, ipfs.Options{ListenAddrs: []string{listen}, Repo: filepath.Join(dir, "blocks")})
	if err != nil {
		return err
	}
	defer node.Close()
	for _, a := range node.Host.Addrs() {
		fmt.Fprintf(out, "listening on %s/p2p/%s\n", a, node.Host.ID())
	}

	if peerAddr != "" {
		addr, err := ma.NewMultiaddr(peerAddr)
		if err != nil {
			return err
		}
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			return err
		}
		if err := node.Connect(ctx, *info); err != nil {
			return fmt.Errorf("connect to %s: %w", peerAddr, err)
		}
		fmt.Fprintln(out, "connected to", info.ID)
	}

	odb, err := orbitdb.New(ctx, orbitdb.Options{IPFS: node, Directory: dir})
	if err != nil {
		return err
	}
	defer odb.Stop()

	opts := []orbitdb.OpenOption{orbitdb.WithType(dbType)}
	if anyone {
		opts = append(opts, orbitdb.WithAccessController(accesscontrollers.IPFS(accesscontrollers.IPFSOptions{Write: []string{"*"}})))
	}
	db, err := odb.Open(ctx, dbName, opts...)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "opened %s database %q\naddress: %s\nidentity: %s\n", db.Type(), db.Name(), db.Address(), odb.Identity().ID)

	sub := db.Events().Subscribe()
	defer sub.Close()
	go func() {
		for ev := range sub.Events() {
			switch ev.Type {
			case databases.EventUpdate:
				fmt.Fprintf(out, "\n* update %s: %v\n> ", ev.Entry.Hash, ev.Entry.Payload)
			case databases.EventJoin:
				fmt.Fprintf(out, "\n* %s joined\n> ", ev.Peer)
			case databases.EventLeave:
				fmt.Fprintf(out, "\n* %s left\n> ", ev.Peer)
			case databases.EventError:
				fmt.Fprintf(out, "\n* error: %v\n> ", ev.Err)
			}
		}
	}()

	fmt.Fprintln(out, `commands: put <key> <value> | get <key> | del <key> | add <value> | all | peers | quit`)
	lines := bufio.NewScanner(in)
	for {
		fmt.Fprint(out, "> ")
		if !lines.Scan() {
			return lines.Err()
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
		fields := strings.Fields(lines.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "quit" || fields[0] == "exit" {
			return nil
		}
		if err := command(ctx, db, fields, out); err != nil {
			fmt.Fprintln(out, "error:", err)
		}
	}
}

var usage = map[string]string{
	"put": "put <key> <value>",
	"get": "get <key>",
	"del": "del <key>",
	"add": "add <value>",
}

func command(ctx context.Context, db databases.Store, fields []string, out io.Writer) error {
	if u, ok := usage[fields[0]]; ok && len(fields) < len(strings.Fields(u)) {
		return fmt.Errorf("usage: %s", u)
	}
	// arg returns the arguments from the i-th on, joined with spaces.
	arg := func(i int) string { return strings.Join(fields[i:], " ") }
	switch fields[0] {
	case "put":
		switch d := db.(type) {
		case *databases.KeyValue:
			_, err := d.Put(ctx, fields[1], arg(2))
			return err
		case *databases.Documents:
			_, err := d.Put(ctx, map[string]any{d.IndexBy(): fields[1], "value": arg(2)})
			return err
		}
	case "get":
		switch d := db.(type) {
		case *databases.KeyValue:
			v, err := d.Get(ctx, arg(1))
			if err == nil {
				fmt.Fprintln(out, v)
			}
			return err
		case *databases.Documents:
			doc, err := d.Get(ctx, arg(1))
			if err == nil {
				fmt.Fprintln(out, doc.Value)
			}
			return err
		}
	case "del":
		switch d := db.(type) {
		case *databases.KeyValue:
			_, err := d.Del(ctx, arg(1))
			return err
		case *databases.Documents:
			_, err := d.Del(ctx, arg(1))
			return err
		}
	case "add":
		if d, ok := db.(*databases.Events); ok {
			_, err := d.Add(ctx, arg(1))
			return err
		}
	case "all":
		switch d := db.(type) {
		case *databases.KeyValue:
			all, err := d.All(ctx)
			for _, kv := range all {
				fmt.Fprintf(out, "%s = %v\n", kv.Key, kv.Value)
			}
			return err
		case *databases.Events:
			all, err := d.All(ctx)
			for _, ev := range all {
				fmt.Fprintln(out, ev.Value)
			}
			return err
		case *databases.Documents:
			all, err := d.All(ctx)
			for _, doc := range all {
				fmt.Fprintln(out, doc.Value)
			}
			return err
		}
	case "peers":
		for _, p := range db.Peers() {
			fmt.Fprintln(out, p)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", fields[0])
	}
	return fmt.Errorf("%q is not supported by %s databases", fields[0], db.Type())
}
