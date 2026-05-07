const ROW_HEIGHT = 28;
const WINDOW_ROWS = 60;

function esc(s) {
  return String(s ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

export class FlowView {
  constructor({ viewportId, innerId, statsId, detailPanel, queryProvider }) {
    this.viewport = document.getElementById(viewportId);
    this.inner = document.getElementById(innerId);
    this.stats = document.getElementById(statsId);
    this.detailPanel = detailPanel;
    this.queryProvider = queryProvider;
    this.events = [];
    this.seenSeqs = new Set();          // dedupe guard against duplicate page fetches
    this.total = 0;
    this.page = 1;
    this.pageSize = 200;
    this.active = new Map();
    this.selectedIndex = -1;
    this.lastSelectedPairSeq = null;
    this.onSelectionChanged = null;

    // Guards against scroll-driven races: scroll fires many times per second,
    // each call could try to fetch the next page concurrently. Without these,
    // multiple in-flight fetches all read the same `this.page` value, all hit
    // the server with the same page number, and all push duplicates → the
    // viewer appears to repeat events and the seq column "loops back".
    this._fetchInFlight = null;          // resolved Promise of the active fetchPage
    this._gen = 0;                       // bumped by reload() to invalidate older fetches

    this.viewport.addEventListener("scroll", () => this.renderVirtual());
  }

  async reload(extra = {}) {
    this._gen += 1;                      // invalidate any fetch responses still in flight
    this._fetchInFlight = null;
    this.page = 1;
    this.events = [];
    this.seenSeqs = new Set();
    this.active.clear();
    this.inner.innerHTML = "";
    this.selectedIndex = -1;
    this.lastSelectedPairSeq = null;
    await this.fetchPage(extra);
    this.renderVirtual();
  }

  async fetchPage(extra = {}) {
    // Coalesce concurrent calls — return the in-flight promise so callers all
    // wait on the same network round-trip instead of issuing duplicates.
    if (this._fetchInFlight) return this._fetchInFlight;
    if (this.total > 0 && this.events.length >= this.total) return undefined;

    const myGen = this._gen;
    const myPage = this.page;
    const base = this.queryProvider();
    const query = `${base}&page=${myPage}&page_size=${this.pageSize}${extra.from_seq ? `&from_seq=${extra.from_seq}` : ""}`;

    this._fetchInFlight = (async () => {
      try {
        const res = await fetch(`/api/flow/stream${query}`);
        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();

        // If reload() ran while we were waiting, our results belong to a
        // stale generation — discard so we don't pollute the new state.
        if (myGen !== this._gen) return;

        // Defensive dedupe — even if the server somehow returns overlapping
        // pages, we only keep events whose seq we haven't seen yet.
        const fresh = [];
        for (const ev of data.events || []) {
          if (this.seenSeqs.has(ev.seq)) continue;
          this.seenSeqs.add(ev.seq);
          fresh.push(ev);
        }
        this.total = data.total || 0;
        this.events.push(...fresh);
        this.inner.style.height = `${this.total * ROW_HEIGHT}px`;
        this.stats.textContent = `zobrazeno ${this.events.length} / ${this.total}`;

        // Advance only if we actually consumed at least one new event.
        // This prevents an infinite loop when the server returns an empty
        // page beyond the real end (or when filtering rejects everything).
        if (fresh.length > 0 && this.events.length < this.total) {
          this.page = myPage + 1;
        } else if (fresh.length === 0) {
          // Stop iterating: either we're caught up or the page is empty.
          this.total = this.events.length;
        }
      } finally {
        this._fetchInFlight = null;
      }
    })();
    return this._fetchInFlight;
  }

  rowClass(e) {
    const sev = e.severity || "ok";
    let cls = `flow-row severity-${sev} event-${e.event_class}`;
    if (e.is_causal_suspect) cls += " suspect";
    if (e.is_chunked) cls += " chunked-parent";
    return cls;
  }

  dirClass(e) {
    if (e.direction === "HOST→DEV") return "host-to-dev";
    if (e.direction === "DEV→HOST") return "dev-to-host";
    return "internal";
  }

  makeRow(e, idx) {
    const row = document.createElement("div");
    row.className = this.rowClass(e);
    if (idx === this.selectedIndex) row.classList.add("selected");
    if (this.lastSelectedPairSeq && e.seq === this.lastSelectedPairSeq) row.classList.add("paired");
    row.style.top = `${idx * ROW_HEIGHT}px`;
    const devTag = `b${e.bus_id ?? 0}/d${e.device_address ?? 0}${e.device_serial ? "|" + esc(e.device_serial) : ""}`;
    row.innerHTML = `<span class="seq">${e.seq}</span> <span>${(e.delta_ms || 0).toFixed(1)}ms</span> <span class="direction ${this.dirClass(e)}">${esc(e.direction)}</span> <span class="dev-tag" title="bus/device${e.device_serial ? ' / serial' : ''}">${devTag}</span> <span>[${esc(e.event_class)}]</span> <span>${esc(e.content)}</span>`;
    row.onclick = () => this.selectIndex(idx);
    return row;
  }

  async selectIndex(idx) {
    if (idx < 0 || idx >= this.events.length) return;
    this.selectedIndex = idx;
    const event = this.events[idx];
    this.lastSelectedPairSeq = event.paired_seq || null;
    await this.detailPanel.showEvent(event);
    if (typeof this.onSelectionChanged === "function") this.onSelectionChanged(event, idx);
    this.renderVirtual();
  }

  async focusSeq(seq) {
    let idx = this.events.findIndex((e) => e.seq === seq);
    let safety = 0;
    while (idx < 0 && this.events.length < this.total && safety < 200) {
      await this.fetchPage();
      idx = this.events.findIndex((e) => e.seq === seq);
      safety += 1;
    }
    if (idx < 0) return;
    this.viewport.scrollTop = Math.max(0, idx * ROW_HEIGHT - this.viewport.clientHeight / 3);
    await this.selectIndex(idx);
  }

  async moveSelection(delta) {
    if (!this.events.length) return;
    const current = this.selectedIndex >= 0 ? this.selectedIndex : 0;
    const next = Math.max(0, Math.min(this.total - 1, current + delta));
    if (next >= this.events.length - 1 && this.events.length < this.total) await this.fetchPage();
    await this.selectIndex(Math.min(next, this.events.length - 1));
  }

  async renderVirtual() {
    const scrollTop = this.viewport.scrollTop;
    const first = Math.floor(scrollTop / ROW_HEIGHT);
    const last = Math.min(this.events.length, first + WINDOW_ROWS);
    if (last + 30 >= this.events.length && this.events.length < this.total) {
      await this.fetchPage();
    }

    // Recompute window after fetch — events array may have grown.
    const first2 = Math.floor(this.viewport.scrollTop / ROW_HEIGHT);
    const last2 = Math.min(this.events.length, first2 + WINDOW_ROWS);

    for (const [idx, el] of this.active.entries()) {
      if (idx < first2 || idx >= last2) {
        el.remove();
        this.active.delete(idx);
      }
    }
    for (let i = first2; i < last2; i += 1) {
      if (this.active.has(i) || !this.events[i]) continue;
      const el = this.makeRow(this.events[i], i);
      this.inner.appendChild(el);
      this.active.set(i, el);
    }
  }
}
