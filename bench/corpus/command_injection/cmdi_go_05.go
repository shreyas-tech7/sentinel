// Practice sample: sh -c with interpolated input.
func resize(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("image")
    out, err := exec.Command("sh", "-c", "convert "+name+" -resize 100x100 out.png").Output()
    write(w, out, err)
}
