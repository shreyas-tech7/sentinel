// Clean sample: parameterized query, argument-list exec, env secret.
func findItem(db *sql.DB, r *http.Request) ([]Item, error) {
    sku := r.URL.Query().Get("sku")
    rows, err := db.Query("SELECT id, label FROM items WHERE sku = $1", sku)
    return scanItems(rows), err
}

func resize(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("image")
    out, err := exec.Command("convert", name, "-resize", "100x100", "out.png").Output()
    write(w, out, err)
}

var apiKey = os.Getenv("PRACTICE_API_KEY")
