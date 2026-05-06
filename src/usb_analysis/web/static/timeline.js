export class FlowTimeline {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext("2d");
    this.onSelectBucket = null;
    this.buckets = [];
    this.canvas.addEventListener("click", (ev) => this.handleClick(ev));
  }

  async load(baseQuery) {
    const res = await fetch(`/api/flow/timeline${baseQuery}&buckets=140`);
    if (!res.ok) return;
    const data = await res.json();
    this.buckets = data.buckets || [];
    this.draw();
  }

  draw() {
    const w = this.canvas.clientWidth || 800;
    const h = this.canvas.height || 90;
    this.canvas.width = w;
    this.ctx.clearRect(0, 0, w, h);
    if (!this.buckets.length) return;
    const max = Math.max(
      1,
      ...this.buckets.map((b) => b.ok_count + b.warn_count + b.error_count + b.reconnect)
    );
    const bw = w / this.buckets.length;
    this.buckets.forEach((b, i) => {
      const x = i * bw;
      const total = b.ok_count + b.warn_count + b.error_count;
      const bar = (total / max) * (h - 10);
      this.ctx.fillStyle = b.error_count ? "#ef4444" : b.warn_count ? "#f59e0b" : "#22c55e";
      this.ctx.fillRect(x, h - bar, Math.max(1, bw - 1), bar);
      if (b.reconnect) {
        this.ctx.fillStyle = "#a855f7";
        this.ctx.fillRect(x, 2, 2, h - 4);
      }
    });
  }

  handleClick(ev) {
    if (!this.buckets.length || !this.onSelectBucket) return;
    const rect = this.canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const idx = Math.max(0, Math.min(this.buckets.length - 1, Math.floor((x / rect.width) * this.buckets.length)));
    this.onSelectBucket(idx, this.buckets.length);
  }
}
