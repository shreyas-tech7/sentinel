// Practice sample: Sprintf-built query handed to db.Query.
func findItem(db *sql.DB, r *http.Request) ([]Item, error) {
    sku := r.URL.Query().Get("sku")
    q := fmt.Sprintf("SELECT id, label FROM items WHERE sku = '%s'", sku)
    rows, err := db.Query(q)
    return scanItems(rows), err
}
