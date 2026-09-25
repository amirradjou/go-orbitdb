`jskeystore/` is the LevelDB keystore fixture `test/fixtures/newtestkeys2` from
[@orbitdb/core](https://github.com/orbitdb/orbitdb) 4.0.0 (MIT). It was written
by the JavaScript implementation; the tests open it to check that Go reads JS
keystores, and derive from its keys the identities and hashes the JavaScript
test suite asserts.
