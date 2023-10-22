// Sorts a vec of items
pub fn merge_sort<T: std::cmp::PartialOrd + Clone>(vector: &Vec<T>) -> Vec<T> {
    // Base case when down to single element in vec
    if vector.len() <= 1 {
        vector.to_vec()
    } else {
        // Split vec in half and call function again, splitting further
        let centre = vector.len() / 2;
        let left = merge_sort(&vector[..centre].to_vec());
        let right = merge_sort(&vector[centre..].to_vec());
        // Combine back up, in sorted order
        merge(&left, &right)
    }
}

// Merge single element vectors into sorted vec
fn merge<T: std::cmp::PartialOrd + Clone>(left: &Vec<T>, right: &Vec<T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();

    // Create iterators to easily remove first item
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();

    loop {
        // Returns bool of whether to add left or right
        let lt = match (left.peek(), right.peek()) {
            (Some(l_val), Some(r_val)) => l_val < r_val,
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
            merge(&vec![1, 5, 10], &vec![2, 4, 12]),
            vec![1, 2, 4, 5, 10, 12]
        )
    }
    #[test]
    fn merge_string() {
        assert_eq!(
            merge(&vec!["A", "C", "D"], &vec!["B", "C", "E"]),
            vec!["A", "B", "C", "C", "D", "E",]
        )
    }

    #[test]
    fn sort_u8() {
        assert_eq!(
            merge_sort(&vec![2, 1, 8, 4, 2, 0, 16, 2]),
            vec![0, 1, 2, 2, 2, 4, 8, 16]
        );
    }

    #[test]
    fn sort_string() {
        assert_eq!(
            merge_sort(&vec![
                String::from("Bulgaria"),
                String::from("France"),
                String::from("Dominica"),
                String::from("Algeria"),
                String::from("Cambodia"),
                String::from("Egypt"),
            ]),
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
    fn sort_empty(){
        assert_eq!(merge_sort(&Vec::<()>::new()), Vec::new())
    }
}