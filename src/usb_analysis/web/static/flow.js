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
    this.pageSize = 1000;                // server max — minimise round-trips
    this.active = new Map();
    this.selectedIndex = -1;
    this.lastSelectedPairSeq = null;
    this.onSelectionChanged = null;
    this.onProgress = null;              // (loaded, total) → void; called during fetchAll

    // Generation counter so a slow fetch from a previous reload() can't
    // corrupt fresh state. Bumped by every reload().
    this._gen = 0;

    this.viewport.addEventListener("scroll", () => this.renderVirtual());
  }

  async reload(extra = {}) {
    this._gen += 1;
    this.page = 1;
    this.events = [];
    this.seenSeqs = new Set();
    this.active.clear();
    this.inner.innerHTML = "";
    this.selectedIndex = -1;
    this.lastSelectedPairSeq = null;
    // Eagerly drain every page so virtual rendering always works against a
    // complete dataset. Lazy on-scroll fetching was unreliable for two
    // reasons: it raced with itself (duplicates) and it required users to
    // scroll just to see later events at all.
    await this.fetchAll(extra);
    this.renderVirtual();
  }

  async fetchAll(extra = {}) {
    const myGen = this._gen;
    let firstExtra = { ...extra };
    let safety = 0;
    while (safety < 1000) {
      if (myGen !== this._gen) return;
      const before = this.events.length;
      await this.fetchPage(firstExtra);
      firstExtra = {};
      safety += 1;
      if (myGen !== this._gen) return;
      if (this.total === 0) break;
      if (this.events.length >= this.total) break;
      if (this.events.length === before) break;     // empty page → stop
      if (typeof this.onProgress === "function") {
        this.onProgress(this.events.length, this.total);
      }
    }
  }

  async fetchPage(extra = {}) {
    if (this.total > 0 && this.events.length >= this.total) return;

    const myGen = this._gen;
    const myPage = this.page;
    const base = this.queryProvider();
    const query = `${base}&page=${myPage}&page_size=${this.pageSize}${extra.from_seq ? `&from_seq=${extra.from_seq}` : ""}`;

    const res = await fetch(`/api/flow/stream${query}`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();

    // Reload happened while we awaited — drop the result.
    if (myGen !== this._gen) return;

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

    // Always advance to the next page, even if `fresh` was empty: an empty
    // batch is normally an indication that the requested page lay past the
    // end of the filtered stream. The outer `fetchAll` loop uses the
    // events-array delta to detect end-of-stream and stop, so we don't risk
    // infinite paging here.
    this.page = myPage + 1;
    if (data.events == null || (data.events.length === 0 && this.events.length < this.total)) {
      // Server claims more events exist but returned an empty page — protect
      // against an infinite loop by clamping total to what we actually saw.
      this.total = this.events.length;
    }
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
    const idx = this.events.findIndex((e) => e.seq === seq);
    if (idx < 0) return;                 // outside the loaded set (filter out of range)
    this.viewport.scrollTop = Math.max(0, idx * ROW_HEIGHT - this.viewport.clientHeight / 3);
    await this.selectIndex(idx);
  }

  async moveSelection(delta) {
    if (!this.events.length) return;
    const current = this.selectedIndex >= 0 ? this.selectedIndex : 0;
    const next = Math.max(0, Math.min(this.events.length - 1, current + delta));
    await this.selectIndex(next);
  }

  renderVirtual() {
    const scrollTop = this.viewport.scrollTop;
    const first = Math.floor(scrollTop / ROW_HEIGHT);
    const last = Math.min(this.events.length, first + WINDOW_ROWS);

    for (const [idx, el] of this.active.entries()) {
      if (idx < first || idx >= last) {
        el.remove();
        this.active.delete(idx);
      }
    }
    for (let i = first; i < last; i += 1) {
      if (this.active.has(i) || !this.events[i]) continue;
      const el = this.makeRow(this.events[i], i);
      this.inner.appendChild(el);
      this.active.set(i, el);
    }
  }
}
