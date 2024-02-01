// Sorts a vec of items
pub fn merge_sort<T, F, K>(vector: &Vec<T>, mut key_fn: F) -> Vec<T>
where
    T: Clone,
    F: FnMut(&T) -> K + Clone,
    K: std::cmp::PartialOrd,
{
    // Base case when down to single element in vec
    if vector.len() <= 1 {
        vector.to_vec()
    } else {
        // Split vec in half and call function again, splitting further
        let centre = vector.len() / 2;
        let left = merge_sort(&vector[..centre].to_vec(), key_fn.clone());
        let right = merge_sort(&vector[centre..].to_vec(), key_fn.clone());
        // Combine back up, in sorted order
        merge(&left, &right, &mut key_fn)
    }
}

// Merge single element vectors into sorted vec
fn merge<T, F, K>(left: &Vec<T>, right: &Vec<T>, mut key_fn: F) -> Vec<T>
where
    T: Clone,
    F: FnMut(&T) -> K,
    K: std::cmp::PartialOrd,
{
    let mut out: Vec<T> = Vec::new();

    // Create iterators to easily remove first item
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();

    loop {
        // Returns bool of whether to add left or right
        let lt = match (left.peek(), right.peek()) {
            (Some(l_val), Some(r_val)) => key_fn(l_val) < key_fn(r_val),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };

        // Item fetched outside match to retain borrowing rules
        // Adds item and advances iterator by 1
        let add = if lt {
            left.next().unwrap()
        } else {
            right.next().unwrap()
        };
        out.push(add.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_u8() {
        assert_eq!(
            merge(&vec![1, 5, 10], &vec![2, 4, 12], |v| *v),
            vec![1, 2, 4, 5, 10, 12]
        )
    }
    #[test]
    fn merge_string() {
        assert_eq!(
            merge(&vec!["A", "C", "D"], &vec!["B", "C", "E"], |v| *v),
            vec!["A", "B", "C", "C", "D", "E"]
        )
    }

    #[test]
    fn sort_u8() {
        assert_eq!(
            merge_sort(&vec![2, 1, 8, 4, 2, 0, 16, 2], |v| *v),
            vec![0, 1, 2, 2, 2, 4, 8, 16]
        );
    }

    #[test]
    fn sort_string() {
        assert_eq!(
            merge_sort(
                &vec![
                    String::from("Bulgaria"),
                    String::from("France"),
                    String::from("Dominica"),
                    String::from("Algeria"),
                    String::from("Cambodia"),
                    String::from("Egypt"),
                ],
                |v| v.clone()
            ),
            vec![
                String::from("Algeria"),
                String::from("Bulgaria"),
                String::from("Cambodia"),
                String::from("Dominica"),
                String::from("Egypt"),
                String::from("France"),
            ]
        );
    }

    #[test]
    fn sort_empty() {
        assert_eq!(merge_sort(&Vec::<()>::new(), |v| *v), Vec::new())
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct TestStruct {
        num: u8,
        str: String,
    }

    #[test]
    fn struct_by_num() {
        let i = TestStruct {
            num: 0,
            str: String::from("Cambodia"),
        };
        let ii = TestStruct {
            num: 1,
            str: String::from("Algeria"),
        };
        let iii = TestStruct {
            num: 2,
            str: String::from("Bulgaria"),
        };
        assert_eq!(
            merge_sort(&vec![ii.clone(), i.clone(), iii.clone()], |v| v.num),
            vec![i, ii, iii]
        )
    }

    #[test]
    fn struct_by_string() {
        let i = TestStruct {
            num: 0,
            str: String::from("Cambodia"),
        };
        let ii = TestStruct {
            num: 1,
            str: String::from("Algeria"),
        };
        let iii = TestStruct {
            num: 2,
            str: String::from("Bulgaria"),
        };
        assert_eq!(
            merge_sort(&vec![i.clone(), ii.clone(), iii.clone()], |v| v.str.clone()),
            vec![ii, iii, i]
        )
    }
}
