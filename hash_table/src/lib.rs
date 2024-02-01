// Crate that provides a hash map structure, which makes use of linked lists

mod linked_list {
    /// Recursive data type linked list that stores key value pairs for hashmap, but may be used for alternate uses
    /// Indexed 'backwards', due to the head being at the 'end' of the list
    #[derive(PartialEq)]
    pub struct LinkedList<K, V> {
        head: Link<K, V>,
    }

    // Link is an alias for the composite type of:
    // Option (so it can contain nothing) of a Box (to allocate data to the heap) of the next Node in the chain
    type Link<K, V> = Option<Box<Node<K, V>>>;

    #[derive(Debug, PartialEq)]
    struct Node<K, V> {
        key: K,
        value: V,
        next: Link<K, V>,
    }

    impl<K: std::cmp::PartialEq, V> LinkedList<K, V> {
        /// Creates a list comprised of no nodes
        pub const fn new() -> Self {
            Self { head: None }
        }

        /// Pushes a key value pair to the list
        /// The head of the list is set as the new key value pair, with the original list being linked to with the next attribute
        pub fn push(&mut self, key: K, val: V) {
            // Take method is used here to move the data, removing need to clone
            let new = Box::new(Node {
                key,
                value: val,
                next: self.head.take(),
            });
            self.head = Some(new);
        }

        /// Returns an Option containing the first value of the list, removing it
        fn pop(&mut self) -> Option<(K, V)> {
            // Check for remaining item
            match self.head.take() {
                Some(n) => {
                    self.head = n.next;
                    Some((n.key, n.value))
                }
                None => None,
            }
        }

        /// Returns an Option containing the index of the item that matches the key
        pub fn get(&self, key: &K) -> Option<usize> {
            let mut node = &self.head;
            let mut i = 0;
            while let Some(n) = node {
                if &n.key == key {
                    return Some(i);
                }
                node = &n.next;
                i += 1;
            }

            None
        }

        /// Returns references to the key and value at an index
        pub fn peek(&self, index: usize) -> (&K, &V) {
            (&self.get_node(index).key, &self.get_node(index).value)
        }

        // Returns a mutable reference to the node at the specified index
        fn get_node(&self, index: usize) -> &Node<K, V> {
            let mut node = &self.head;
            let mut i = 0;
            // Simple recursion to get to the node at index
            while let Some(n) = node {
                if i == index {
                    return n;
                }

                node = &n.next;
                i += 1;
            }

            // Throw error if index too large
            panic!("Index out of bounds")
        }

        // Similar to the [get_node] method, but returns a mutable reference
        fn get_node_mut(&mut self, index: usize) -> &mut Node<K, V> {
            let mut node = &mut self.head;
            let mut i = 0;
            while let Some(n) = node {
                if i == index {
                    return n;
                }

                node = &mut n.next;
                i += 1;
            }

            // Throw error if index too large
            panic!("Index out of bounds")
        }

        /// Remove an item located at an index
        pub fn remove(&mut self, index: usize) {
            // More efficient to simply pop the list if index the first value
            if index == 0 {
                self.pop();
            } else {
                // Fetches a mutable reference to the node at the index and assigns to it using a dereference
                let node = &mut self.get_node_mut(index - 1).next;
                *node = if let Some(n) = node.take() {
                    n.next
                } else {
                    // Throw error if index invalid
                    panic!("Index out of bounds")
                }
            }
        }
    }

    // Allows for easy printout
    // Ex/ [(20, 82), (21, 05), (22, 40), (34, 15)]
    impl<K: std::fmt::Debug, V: std::fmt::Debug> std::fmt::Debug for LinkedList<K, V> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut out = String::new();
            let mut node = &self.head;
            // For each node, appends "(k, v), "" to the final string
            while let Some(ref n) = node {
                out += format!("({:?}, {:?}), ", n.key, n.value).as_str();
                node = &n.next;
            }
            // Remove trailing comma
            write!(f, "[{}]", out.trim_end_matches(", "))
        }
    }

    #[allow(unused_macros)]
    /// Makes a linked list of key value pairs from a list of tuples
    macro_rules! ll {
        // Matches any length list passed in
    ( $( $x:expr ),* ) => {
        {
            // Created new list, pushes all items to it, then returns the list
            let mut temp = LinkedList::new();
            $(
                temp.push($x.0, $x.1);
            )*
            temp
        }
    };
}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn new() {
            assert_eq!(LinkedList::<u8, u8>::new(), LinkedList { head: None })
        }

        #[test]
        fn add() {
            let mut list = LinkedList::new();
            list.push(20, 82);
            assert_eq!(list, ll!((20, 82)))
        }

        #[test]
        fn add_macro() {
            let list = ll![((), 20), ((), 82)];
            assert_eq!(
                list,
                LinkedList {
                    head: Some(Box::new(Node {
                        key: (),
                        value: 82,
                        next: Some(Box::new(Node {
                            key: (),
                            value: 20,
                            next: None
                        }))
                    }))
                }
            )
        }

        #[test]
        fn pop() {
            let mut list = ll![(20, 82), (21, 05), (22, 40), (34, 15)];
            list.pop();
            assert_eq!(list, ll![(20, 82), (21, 05), (22, 40)])
        }

        #[test]
        fn get_success() {
            let list = ll![(20, 82), (21, 05), (22, 40), (34, 15)];
            // Indexes are backwards
            assert_eq!(list.get(&21), Some(2))
        }

        #[test]
        fn get_last_success() {
            let list = ll![(20, 82), (21, 05), (22, 40), (34, 15)];
            // Indexes are backwards
            assert_eq!(list.get(&20), Some(3))
        }

        #[test]
        fn get_fail() {
            let list = ll![(20, 82), (21, 05), (22, 40), (34, 15)];
            assert_eq!(list.get(&14), None)
        }

        #[test]
        fn remove_mid() {
            let mut list = ll![(20, 82), (21, 05), (22, 40), (34, 15)];
            list.remove(2);
            assert_eq!(list, ll![(20, 82), (22, 40), (34, 15)])
        }

        #[test]
        fn remove_start() {
            let mut list = ll![(20, 82), (21, 05), (22, 40), (34, 15)];
            list.remove(0);
            assert_eq!(list, ll![(20, 82), (21, 05), (22, 40)])
        }

        #[test]
        fn print() {
            println!("{:?}", ll![(20, 82), (21, 05), (22, 40), (34, 15)]);
        }

        #[test]
        fn mismatched_types() {
            let mut list = ll![
                (4, String::from("Algeria")),
                (0, String::from("Bulgaria")),
                (-8, String::from("Cambodia"))
            ];
            let i = list.get(&-8).unwrap();
            list.remove(i);
            assert_eq!(
                list,
                ll!((4, String::from("Algeria")), (0, String::from("Bulgaria")))
            )
        }
    }
}

pub mod hash_map {
    use crate::linked_list::LinkedList;
    use hash::Hashable;

    /// A static HashMap type utilising linked lists
    /// Rehashing is not implemented, meaning the size of the structure cannot be changed after instantiation
    /// The size attribute holds the number of buckets held by the type, with a greater number of buckets reducing the number of potential collisions
    #[derive(Debug)]
    pub struct HashMap<K: std::cmp::PartialEq, V> {
        pub size: usize,
        buckets: Vec<LinkedList<K, V>>,
    }

    // All key comparison is done from HashMap, as the linked list's K type doesn't require PartialEq
    impl<K: std::cmp::PartialEq + Hashable, V> HashMap<K, V> {
        /// Creates a new [HashMap] with the specified number of buckets
        pub fn new_with_size(size: usize) -> Self {
            let mut buckets = Vec::new();
            // Matches with an _ to not bind count index to a variable that won't be used
            for _ in 0..size {
                buckets.push(LinkedList::new())
            }
            Self {
                size: size,
                buckets,
            }
        }

        /// Adds a new key value pair to the map
        pub fn insert(&mut self, key: K, value: V) {
            let hashed = Self::hash_key(&key);

            // Hash value turned into index by performing modulo operation with the number of buckets stored
            let i = hashed as usize % self.size;
            self.buckets[i].push(key, value)
        }

        /// Returns an Option containing the value for a given key
        pub fn get(&self, key: &K) -> Option<&V> {
            let hashed = Self::hash_key(&key);

            let i = hashed as usize % self.size;
            let ll = &self.buckets[i];

            // Tries to find key within linked list at index for the key
            if let Some(index) = ll.get(&key) {
                Some(&ll.peek(index).1)
            } else {
                None
            }
        }

        /// Deletes a key value pair from the map, given a key
        pub fn remove(&mut self, key: &K) {
            let hashed = Self::hash_key(&key);

            let i = hashed as usize % self.size;
            let ll = &mut self.buckets[i];
            if let Some(index) = ll.get(&key) {
                ll.remove(index)
            } else {
                // Panics if key doesn't exist
                panic!("Attempted to remove non existant item")
            }
        }

        // Generates an index into the vector of buckets using a SHA256 hash
        fn hash_key(key: &K) -> u64 {
            // SHA256 always returns 256 bits, so safe to call unwrap
            let hashed: [u8; 8] = hash::HashFn::SHA256.digest(key)[..8]
                .try_into()
                .unwrap();
            // Interprets the array as a big-endian u64 value
            u64::from_be_bytes(hashed)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn new() {
            let map: HashMap<String, u8> = HashMap::new_with_size(5);
            assert_eq!(map.size, 5)
        }

        #[test]
        fn get_success() {
            let mut map = HashMap::new_with_size(5);
            map.insert(String::from("Primm"), 14);
            map.insert(String::from("Manonam"), 2082);
            map.insert(String::from("Secret"), 14);
            assert_eq!(map.get(&String::from("Primm")).unwrap(), &14)
        }

        #[test]
        fn get_fail() {
            let mut map = HashMap::new_with_size(5);
            map.insert(String::from("Primm"), 14);
            map.insert(String::from("Manonam"), 2082);
            map.insert(String::from("Secret"), 14);
            assert_eq!(map.get(&String::from("Pressure")), None)
        }

        #[test]
        fn remove() {
            let mut map = HashMap::new_with_size(5);
            map.insert(String::from("Primm"), 14);
            map.insert(String::from("Manonam"), 2082);
            assert_eq!(map.get(&String::from("Manonam")).unwrap(), &2082);
            map.remove(&String::from("Manonam"));
            assert_eq!(map.get(&String::from("Manonam")), None)
        }

        #[test]
        fn any_struct() {
            struct S {}

            let mut map = HashMap::new_with_size(5);
            map.insert(String::from("Manonam"), S {});
            map.get(&String::from("Manonam")).unwrap();
        }
    }
}
