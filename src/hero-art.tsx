import { useEffect, useRef } from "react";

const vertexSource = `
  attribute vec2 position;
  void main() { gl_Position = vec4(position, 0.0, 1.0); }
`;

const fragmentSource = `
  precision mediump float;
  uniform vec2 resolution;
  uniform float time;

  void main() {
    vec2 p = (2.0 * gl_FragCoord.xy - resolution) / resolution.y;
    p = mat2(0.88, -0.48, 0.48, 0.88) * p;
    p.y *= 1.5;

    float angle = atan(p.y, p.x);
    float radius = length(p);
    float phase = angle + time * 0.25;
    float ribbon = radius - 0.79 - 0.10 * sin(3.0 * phase) - 0.035 * cos(5.0 * phase);
    float envelope = exp(-abs(ribbon) * 10.0);
    float spacing = ribbon * 88.0 + sin(phase * 4.0) * 0.6;
    float threads = pow(0.5 + 0.5 * cos(spacing), 5.0);
    float rim = exp(-abs(ribbon + 0.075) * 42.0);
    float light = 0.57 + 0.43 * cos(2.0 * phase - 0.7);
    float hue = 0.5 + 0.5 * cos(phase + ribbon * 3.0 + 0.7);
    vec3 emerald = vec3(0.19, 0.80, 0.61);
    vec3 chartreuse = vec3(0.81, 1.0, 0.49);
    vec3 tint = mix(emerald, chartreuse, hue);
    float glow = envelope * (0.19 + threads * 0.75) * light + rim * 0.18;
    float vignette = 1.0 - smoothstep(0.82, 1.19, abs(p.y / 1.5));

    gl_FragColor = vec4(tint, min(0.95, glow * vignette));
  }
`;

function compile(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
  gl.deleteShader(shader);
  return null;
}

export function HeroArt() {
  const surface = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = surface.current;
    const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
    const phone = matchMedia("(max-width: 720px), (pointer: coarse)");
    const network = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection;
    if (!canvas || network?.saveData) return;

    const gl = canvas.getContext("webgl", {
      alpha: true,
      antialias: false,
      depth: false,
      powerPreference: "low-power",
      premultipliedAlpha: false,
      stencil: false,
      failIfMajorPerformanceCaveat: true,
    });
    if (!gl) return;

    const vertex = compile(gl, gl.VERTEX_SHADER, vertexSource);
    const fragment = compile(gl, gl.FRAGMENT_SHADER, fragmentSource);
    const program = gl.createProgram();
    const buffer = gl.createBuffer();
    const dispose = () => {
      gl.deleteShader(vertex);
      gl.deleteShader(fragment);
      gl.deleteProgram(program);
      gl.deleteBuffer(buffer);
    };
    if (!vertex || !fragment || !program || !buffer) {
      dispose();
      return;
    }
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      dispose();
      return;
    }
    gl.useProgram(program);
    const position = gl.getAttribLocation(program, "position");
    const resolution = gl.getUniformLocation(program, "resolution");
    const time = gl.getUniformLocation(program, "time");
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);

    let frame = 0;
    let lastDraw = 0;
    let shaderTime = 0;
    const started = performance.now();

    function draw() {
      if (!canvas || !gl || gl.isContextLost()) return;
      const { clientWidth, clientHeight } = canvas;
      if (!clientWidth || !clientHeight) return;
      const pixelBudget = phone.matches ? 65_000 : 145_000;
      const scale = Math.min(1, Math.sqrt(pixelBudget / (clientWidth * clientHeight)));
      const width = Math.max(1, Math.round(clientWidth * scale));
      const height = Math.max(1, Math.round(clientHeight * scale));
      if (canvas.width !== width) canvas.width = width;
      if (canvas.height !== height) canvas.height = height;
      gl.viewport(0, 0, width, height);
      gl.uniform2f(resolution, width, height);
      gl.uniform1f(time, shaderTime);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      canvas.dataset.rendered = "true";
    }

    function stop() {
      cancelAnimationFrame(frame);
    }

    function animate(now: number) {
      const progress = Math.min(1, (now - started) / 1450);
      if (now - lastDraw >= 32 || progress === 1) {
        shaderTime = 1 - (1 - progress) ** 3;
        draw();
        lastDraw = now;
      }
      if (progress < 1) frame = requestAnimationFrame(animate);
    }

    function updateMotion() {
      if (reducedMotion.matches || phone.matches || document.hidden) stop();
      draw();
    }

    function showFallback() {
      stop();
      surface.current?.removeAttribute("data-rendered");
    }

    const resize = new ResizeObserver(draw);
    resize.observe(canvas);
    canvas.addEventListener("webglcontextlost", showFallback);
    reducedMotion.addEventListener("change", updateMotion);
    phone.addEventListener("change", updateMotion);
    document.addEventListener("visibilitychange", updateMotion);
    draw();
    if (!reducedMotion.matches && !phone.matches && !document.hidden) {
      frame = requestAnimationFrame(animate);
    }

    return () => {
      stop();
      resize.disconnect();
      canvas.removeEventListener("webglcontextlost", showFallback);
      reducedMotion.removeEventListener("change", updateMotion);
      phone.removeEventListener("change", updateMotion);
      document.removeEventListener("visibilitychange", updateMotion);
      dispose();
    };
  }, []);

  return <div className="hero-art" aria-hidden="true">
    <div className="hero-orbit" />
    <canvas ref={surface} />
  </div>;
}
