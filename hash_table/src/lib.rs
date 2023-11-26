mod linked_list {
    // Recursive data type linked list
    // Avioding recursive functions as would limit to 127 nodes
    // Indexed 'backwards'
    #[derive(PartialEq)]
    pub struct LinkedList<T> {
        head: Link<T>,
    }

    type Link<T> = Option<Box<Node<T>>>;

    #[derive(Debug, PartialEq)]
    struct Node<T> {
        value: T,
        next: Link<T>,
    }

    impl<T: std::cmp::PartialEq> LinkedList<T> {
        pub const fn new() -> Self {
            Self { head: None }
        }

        pub fn push(&mut self, val: T) {
            let new = Box::new(Node {
                value: val,
                next: self.head.take(),
            });
            self.head = Some(new);
        }

        fn pop(&mut self) -> Option<T> {
            match self.head.take() {
                Some(n) => {
                    self.head = n.next;
                    Some(n.value)
                }
                None => None,
            }
        }

        fn get(&self, val: T) -> Option<usize> {
            let mut node = &self.head;
            let mut i = 0;
            while let Some(n) = node {
                if n.value == val {
                    return Some(i);
                }
                node = &n.next;
                i += 1;
            }

            None
        }

        pub fn get_from_closure<F>(&self, mut key_fn: F) -> Option<usize>
        where
            F: FnMut(&T) -> bool,
        {
            let mut node = &self.head;
            let mut i = 0;
            while let Some(n) = node {
                if key_fn(&n.value) {
                    return Some(i);
                }
                node = &n.next;
                i += 1;
            }

            None
        }

        pub fn peek(&self, index: usize) -> &T {
            &self.get_node(index).value
        }

        fn get_node(&self, index: usize) -> &Node<T> {
            let mut node = &self.head;
            let mut i = 0;
            while let Some(n) = node {
                if i == index {
                    return n;
                }

                node = &n.next;
                i += 1;
            }

            panic!("Index out of bounds")
        }

        fn get_node_mut(&mut self, index: usize) -> &mut Node<T> {
            let mut node = &mut self.head;
            let mut i = 0;
            while let Some(n) = node {
                if i == index {
                    return n;
                }

                node = &mut n.next;
                i += 1;
            }

            panic!("Index out of bounds")
        }

        pub fn remove(&mut self, index: usize) {
            if index == 0 {
                self.pop();
            } else {
                let node = &mut self.get_node_mut(index - 1).next;
                *node = if let Some(n) = node.take() {
                    n.next
                } else {
                    panic!("Index out of bounds")
                }
            }
        }
    }

    // Allows for easy printout
    impl<T: std::fmt::Debug> std::fmt::Debug for LinkedList<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut out = String::new();
            let mut node = &self.head;
            while let Some(ref n) = node {
                out += format!("{:?}, ", n.value).as_str();
                node = &n.next;
            }
            // Remove trailing comma
            write!(f, "[{}]", out.trim_end_matches(", "))
        }
    }

    macro_rules! ll {
    ( $( $x:expr ),* ) => {
        {
            let mut temp = LinkedList::new();
            $(
                temp.push($x);
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
            assert_eq!(LinkedList::<u8>::new(), LinkedList { head: None })
        }

        #[test]
        fn add() {
            let mut list = LinkedList::new();
            list.push(14);
            assert_eq!(list, ll!(14))
        }

        #[test]
        fn add_macro() {
            let list = ll![20, 82];
            assert_eq!(
                list,
                LinkedList {
                    head: Some(Box::new(Node {
                        value: 82,
                        next: Some(Box::new(Node {
                            value: 20,
                            next: None
                        }))
                    }))
                }
            )
        }

        #[test]
        fn pop() {
            let mut list = ll![20, 82, 21, 05];
            list.pop();
            assert_eq!(list, ll![20, 82, 21])
        }

        #[test]
        fn get_success() {
            let list = ll![20, 82, 21, 05];
            // Indexes are backwards
            assert_eq!(list.get(21), Some(1))
        }

        #[test]
        fn get_last_success() {
            let list = ll![20, 82, 21, 05];
            // Indexes are backwards
            assert_eq!(list.get(20), Some(3))
        }

        #[test]
        fn get_fail() {
            let list = ll![20, 82, 21, 05];
            assert_eq!(list.get(14), None)
        }

        #[test]
        fn remove_mid() {
            let mut list = ll![20, 82, 21, 05];
            list.remove(2);
            assert_eq!(list, ll![20, 21, 05])
        }

        #[test]
        fn remove_start() {
            let mut list = ll![20, 82, 21, 05];
            list.remove(0);
            assert_eq!(list, ll![20, 82, 21])
        }

        #[test]
        fn print() {
            println!("{:?}", ll![20, 82, 21, 05]);
        }

        #[test]
        fn tuple() {
            let mut list = ll!(
                (4, String::from("Algeria")),
                (0, String::from("Bulgaria")),
                (-8, String::from("Cambodia"))
            );
            let i = list.get_from_closure(|x| x.0 == -8).unwrap();
            list.remove(i);
            assert_eq!(
                list,
                ll!((4, String::from("Algeria")), (0, String::from("Bulgaria")))
            )
        }
    }
}

mod hash_map {
    use crate::linked_list::LinkedList;
    use hash::Hashable;

    #[derive(Debug)]
    pub struct HashMap<K: std::cmp::PartialEq, V: std::cmp::PartialEq> {
        pub size: usize,
        buckets: Vec<LinkedList<(K, V)>>,
    }

    impl<K: std::cmp::PartialEq + Hashable, V: std::cmp::PartialEq> HashMap<K, V> {
        fn new_with_size(size: usize) -> Self {
            let mut buckets = Vec::new();
            for _ in 0..size {
                buckets.push(LinkedList::new())
            }
            Self {
                size: size,
                buckets,
            }
        }

        fn insert(&mut self, key: K, value: V) {
            // SHA256 always returns 256 bits
            let hashed: [u8; 8] = hash::HashFn::SHA256.digest(&key.to_message())[..8]
                .try_into()
                .unwrap();
            let hashed = u64::from_be_bytes(hashed) as usize;

            let i = hashed % self.size;
            self.buckets[i].push((key, value))
        }

        fn get(&self, key: &K) -> Option<&V> {
            let hashed = Self::hash_key(&key);

            let i = hashed as usize % self.size;
            let ll = &self.buckets[i];
            if let Some(index) = ll.get_from_closure(|x| &x.0 == key) {
                Some(&ll.peek(index).1)
            } else {
                None
            }
        }

        fn remove(&mut self, key: &K) {
            let hashed = Self::hash_key(&key);

            let i = hashed as usize % self.size;
            let ll = &mut self.buckets[i];
            if let Some(index) = ll.get_from_closure(|x| &x.0 == key) {
                ll.remove(index)
            } else {
                panic!("Attempted to remove non existant item")
            }
        }

        fn hash_key(key: &K) -> u64 {
            let hashed: [u8; 8] = hash::HashFn::SHA256.digest(&key.to_message())[..8]
                .try_into()
                .unwrap();
            u64::from_be_bytes(hashed)
        }
    }

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
            #[derive(PartialEq, Debug)]
            struct S {
                val: u16,
            }

            let mut map = HashMap::new_with_size(5);
            map.insert(String::from("Manonam"), S{val:2082});
            assert_eq!(map.get(&String::from("Manonam")).unwrap(), &S{val:2082});
        }
    }
}
