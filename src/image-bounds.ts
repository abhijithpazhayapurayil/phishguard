const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];
export const MAX_IMAGE_BYTES = 12 * 1024 * 1024;
const MAX_IMAGE_PIXELS = 24_000_000;
const MAX_IMAGE_SIDE = 9000;
const SOF = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

export function imageDimensions(bytes: ArrayBuffer): { width: number; height: number } {
  const view = new DataView(bytes);
  let width = 0;
  let height = 0;
  if (view.byteLength >= 24
    && PNG_SIGNATURE.every((value, index) => view.getUint8(index) === value)
    && view.getUint32(12) === 0x49484452) {
    width = view.getUint32(16);
    height = view.getUint32(20);
  } else if (view.byteLength >= 2 && view.getUint16(0) === 0xffd8) {
    let offset = 2;
    while (offset + 4 <= view.byteLength && view.getUint8(offset++) === 0xff) {
      while (offset < view.byteLength && view.getUint8(offset) === 0xff) offset++;
      if (offset + 3 > view.byteLength) break;
      const marker = view.getUint8(offset++);
      if (marker === 0xda || marker === 0xd9) break;
      const length = view.getUint16(offset);
      if (length < 2 || offset + length > view.byteLength) break;
      if (SOF.has(marker) && length >= 8) {
        height = view.getUint16(offset + 3);
        width = view.getUint16(offset + 5);
        break;
      }
      offset += length;
    }
  }
  if (!width || !height) throw new Error("Choose a readable PNG or JPEG screenshot.");
  if (width * height > MAX_IMAGE_PIXELS || Math.max(width, height) > MAX_IMAGE_SIDE) {
    throw new Error("That screenshot is too large. Crop it around the message and try again.");
  }
  return { width, height };
}
