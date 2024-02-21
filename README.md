# art

Implementation of the Asynchronous Ratcheting Tree data structure and
associated protocols, based on the CCS'19 paper "On Ends-to-Ends Encrytpion" by
Cohn-Gordon, et al.

# Building

To build the command-line utilities, do:

```
make
```

There is a also a `clean` target to delete these built utilities:

```
make clean
```

# Running

1. Start with generating identity and ephemeral keys for the participants

   ```bash
   # Generating individually
   ./genpkey -keytype ek alice
   ./genpkey -keytype ik alice

   # Generating in bulk
   for name in alice bob cici dave; do for type in ik ek; do ./genpkey -keytype $type $name; done; done
   ```

   Move the certificates to data folder after generation.

   ```bash
   mv *.pem cmd/setup_group/data/
   ```

2. Initiating Group Setup (initiator here = alice)
   ```
   ./setup_group -initiator alice ./cmd/setup_group/data/4.conf ./cmd/setup_group/data/alice-ik.pem
   ```
3. For processing the setup message by another participant (participant here = bob, index = 2)
   ```
   ./processmsg -setup ./4.conf.dir/setup.msg -pk ./cmd/setup_group/data/alice-ik-pub.pem 2 ./cmd/setup_group/data/bob-ek.pem bob_tree_state
   ```
4. Update Key: Cici updates her key

   ```
   ./update_key -u cici_update_key 3 ./cmd/setup_group/data/cici-ek.pem cici_state
   ```

5. Process Update Message: Bob applies the key update message sent by Cici in Step 4

   ```
   ./process_update_message 2 ./cmd/setup_group/data/bob-ek.pem bob_state cici_update_key
   ```
