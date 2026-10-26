// iconkit.js: render Alfred result icons with AppKit (JavaScript for Automation, built into macOS).
//
//   osascript -l JavaScript iconkit.js <jobs.json>      prints "<rendered>/<jobs>"
//
// jobs.json is a list of icons to render (256x256 PNG). Each job has "out" plus one look:
//   {"out": p, "base": "/path/App.app", "badge": {"text": "RE", "color": "#1D4ED8"}}
//       an app's or file's own icon with a monogram badge in the bottom-right corner
//   {"out": p, "bg": "#15803D", "symbol": "lock.fill"}   white SF Symbol on a rounded square
//   {"out": p, "bg": "#1D4ED8", "text": "AC"}            white monogram on a rounded square
// Text shrinks to fit, so "8080" or "R3" work as well as "AC".
ObjC.import('AppKit');

const S = 256;
const WHITE = $.NSColor.whiteColor;

function rgb(hex) {
  const n = parseInt(hex.replace('#', ''), 16);
  return $.NSColor.colorWithSRGBRedGreenBlueAlpha(((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255, 1);
}

function fillRounded(x, y, w, h, r, color) {
  color.setFill;
  $.NSBezierPath.bezierPathWithRoundedRectXRadiusYRadius($.NSMakeRect(x, y, w, h), r, r).fill;
}

function drawText(text, rect, maxSize) {
  let size = maxSize, font, attrs, sz;
  for (;;) {
    font = $.NSFont.systemFontOfSizeWeight(size, 0.56);  // 0.56 = NSFontWeightHeavy (constant doesn't bridge)
    // Built key by key: ObjC objects inside a JS array get converted to dictionaries.
    attrs = $.NSMutableDictionary.alloc.init;
    attrs.setObjectForKey(font, 'NSFont');
    attrs.setObjectForKey(WHITE, 'NSColor');
    sz = $.NSString.alloc.initWithString(text).sizeWithAttributes(attrs);
    if (sz.width <= rect.w * 0.84 || size < 20) break;
    size -= 4;
  }
  // drawAtPoint takes the line box's bottom-left; the baseline sits -descender above it.
  // Centre the capitals, not the line box, so monograms look centred.
  const baseline = rect.y + (rect.h - font.capHeight) / 2;
  $.NSString.alloc.initWithString(text).drawAtPointWithAttributes(
    $.NSMakePoint(rect.x + (rect.w - sz.width) / 2, baseline + font.descender), attrs);
}

function drawSymbol(name, rect) {
  let img = $.NSImage.imageWithSystemSymbolNameAccessibilityDescription(name, name);
  if (!img || img.isNil()) throw new Error('unknown SF Symbol: ' + name);
  img = img.imageWithSymbolConfiguration(
    $.NSImageSymbolConfiguration.configurationWithPointSizeWeight(rect.h, 0.3));  // 0.3 = semibold
  const tinted = img.copy;
  tinted.lockFocus;
  WHITE.set;
  $.NSRectFillUsingOperation($.NSMakeRect(0, 0, tinted.size.width, tinted.size.height), $.NSCompositingOperationSourceAtop);
  tinted.unlockFocus;
  const scale = Math.min(rect.w / tinted.size.width, rect.h / tinted.size.height);
  const w = tinted.size.width * scale, h = tinted.size.height * scale;
  tinted.drawInRectFromRectOperationFraction(
    $.NSMakeRect(rect.x + (rect.w - w) / 2, rect.y + (rect.h - h) / 2, w, h),
    $.NSZeroRect, $.NSCompositingOperationSourceOver, 1);
}

function render(job) {
  const rep = $.NSBitmapImageRep.alloc.initWithBitmapDataPlanesPixelsWidePixelsHighBitsPerSampleSamplesPerPixelHasAlphaIsPlanarColorSpaceNameBytesPerRowBitsPerPixel(
    null, S, S, 8, 4, true, false, $.NSDeviceRGBColorSpace, 0, 0);
  $.NSGraphicsContext.saveGraphicsState;
  $.NSGraphicsContext.setCurrentContext($.NSGraphicsContext.graphicsContextWithBitmapImageRep(rep));

  if (job.base) {
    const icon = $.NSWorkspace.sharedWorkspace.iconForFile(job.base);
    icon.setSize($.NSMakeSize(S, S));
    icon.drawInRectFromRectOperationFraction($.NSMakeRect(0, 0, S, S), $.NSZeroRect, $.NSCompositingOperationSourceOver, 1);
  } else {
    fillRounded(S * 0.06, S * 0.06, S * 0.88, S * 0.88, S * 0.2, rgb(job.bg || '#4B5563'));
  }
  const inner = {x: S * 0.12, y: S * 0.12, w: S * 0.76, h: S * 0.76};
  if (job.symbol) drawSymbol(job.symbol, {x: S * 0.22, y: S * 0.22, w: S * 0.56, h: S * 0.56});
  if (job.text) drawText(job.text, inner, S * 0.42);
  if (job.badge) {
    // Bottom-right badge with a white rim, big enough to read at Alfred's ~32 pt row size.
    const b = {x: S * 0.30, y: S * 0.02, w: S * 0.68, h: S * 0.50};
    fillRounded(b.x - 6, b.y - 6, b.w + 12, b.h + 12, S * 0.13, WHITE);
    fillRounded(b.x, b.y, b.w, b.h, S * 0.11, rgb(job.badge.color));
    drawText(job.badge.text, b, S * 0.30);
  }

  $.NSGraphicsContext.restoreGraphicsState;
  const png = rep.representationUsingTypeProperties($.NSBitmapImageFileTypePNG, $());
  // Write then rename, so a reader never sees a half-written icon.
  const tmp = job.out + '.tmp';
  if (!png.writeToFileAtomically(tmp, false)) throw new Error('cannot write ' + tmp);
  $.rename(tmp, job.out);
}

ObjC.import('stdio');  // rename(2)

function run(argv) {
  const jobs = JSON.parse($.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null).js);
  let ok = 0;
  for (const job of jobs) {
    try { render(job); ok++; } catch (e) { console.log('iconkit: ' + job.out + ': ' + e); }
  }
  return ok + '/' + jobs.length;
}
