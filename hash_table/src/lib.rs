mod linked_list {
    // Recursive data type linked list
    // Avioding recursive functions as would limit to 127 nodes
    // Indexed 'backwards'
    #[derive(PartialEq)]
    struct LinkedList<T> {
        head: Link<T>,
    }

    type Link<T> = Option<Box<Node<T>>>;

    #[derive(Debug, PartialEq)]
    struct Node<T> {
        value: T,
        next: Link<T>,
    }

    impl<T: std::cmp::PartialEq> LinkedList<T> {
        fn new() -> Self {
            Self { head: None }
        }

        fn push(&mut self, val: T) {
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

        fn get_from_closure<F>(&self, mut key_fn: F) -> Option<usize>
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

        fn remove(&mut self, index: usize) {
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

        mod list {
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
}
