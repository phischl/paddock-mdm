# 0018 — List and confirmation conventions for portal and admin API
Status: Accepted (product owner, 2026-10-03)

## Context
The product owner requires, for the whole portal: **never** browser-native confirmations, always a modal; **every**
list with pagination, search, sorting, filtering and a selectable number of items per page. M0 shipped cursor-based
"next page" lists without search, sorting or page size selection. The rule needs a uniform API contract so every
list behaves the same and a new list cannot forget a capability.

## Options
- **Offset pagination (`page`, `page_size`, `total`) with a capped total.** + Page numbers, jump to page, items per
  page, trivially uniform; − deep offsets get slower on very large tables (audit log).
- **Keyset/cursor pagination with sort.** + Constant cost at any depth; − no page numbers or "page X of Y", awkward
  with arbitrary sort fields, two different UI behaviours if mixed.
- **Mixed (offset for small lists, keyset for the audit log).** − Two contracts, two UI components; violates "every
  list the same".

## Decision
**One list contract for every collection endpoint** of the admin API (`GET` on a collection):

| Parameter | Rule |
| --- | --- |
| `page` | integer ≥ 1, default 1 |
| `page_size` | one of `10, 25, 50, 100`, default `25`; any other value → 400 `invalid_request` |
| `sort` | one field from the endpoint's documented allow list; prefix `-` = descending; default documented per endpoint; the server always appends the primary key as tie-breaker for a stable order |
| `q` | optional free-text search, 2–100 characters, case-insensitive substring match over the endpoint's documented search fields |
| filters | endpoint-specific query parameters, documented in OpenAPI; enum filters are repeatable (`status=active&status=suspended`) |

Response envelope:

```json
{ "items": [], "page": 1, "page_size": 25, "total": 137, "total_capped": false, "sort": "-created_at" }
```

- **Depth limit:** `page × page_size` MUST NOT exceed 10 000 (400 `page_out_of_range`). `total` is counted with a cap
  of 10 000; above it `total = 10000` and `total_capped = true`, and the UI shows "10,000+" and asks to narrow the
  filters. This bounds the cost of offset pagination on large tables.
- **Search implementation:** `ILIKE` over the documented fields; tables expected to exceed 100 000 rows per
  organization get a `pg_trgm` GIN index on the searched expressions (PostgreSQL contrib, no new service).
- **OpenAPI:** shared components `PageParam`, `PageSizeParam`, `SortParam`, `SearchParam` and a generic page schema;
  each list endpoint documents its sort allow list and search fields with the extension
  `x-paddock-list: { sort: [...], default_sort: "...", search: [...], filters: [...] }`. A contract test fails if a
  collection `GET` lacks the parameters or the extension.

**Portal:**
- One shared list component (`DataList`, built on Vuetify's server-side data table) for every list: search field
  (debounced 300 ms), filter controls, sortable column headers, pagination with page numbers and an items-per-page
  selector (10/25/50/100), loading, empty and error states. List state (page, page size, sort, search, filters) lives
  in the URL query so reload, back button and shared links keep it.
- **No browser-native dialogs.** `window.confirm`, `window.alert`, `window.prompt` and `beforeunload` prompts are
  forbidden (ESLint `no-alert: error`, plus a restricted-globals rule). Every destructive, irreversible or
  security-relevant action is confirmed in a modal (`ConfirmDialog`, Vuetify `v-dialog`): title, consequence in one
  sentence, focus on *Cancel* by default, destructive button in the error colour. High-risk actions (later: Lock,
  Destroy, reveal of the local admin password) additionally require typing the target's name. Errors and success
  messages use inline alerts or snackbars, never `alert()`.

## Consequences
+ Uniform behaviour and one component; new lists get all capabilities by construction; contract test enforces it.
− Breaking change of the M0 list endpoints (`cursor`/`limit` → `page`/`page_size`) — acceptable before the first release.
− Offset cost on deep pages is bounded by the 10 000 limit; very large audit exports go through a separate export
  function (later milestone), not through paging.
