// Practice sample: Angular security-bypass on a request-backed value.
export class SearchResultComponent {
  render(query: { body: { markup: string } }) {
    this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(query.body.markup);
  }
}
