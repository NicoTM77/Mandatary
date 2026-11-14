import assert from 'node:assert/strict';

/* global document, window, getComputedStyle, Node, NodeFilter, requestAnimationFrame */

// Dependency-free structural accessibility audit for the browser tests (P1.16.4).
//
// This is NOT axe-core and NOT a WCAG-conformance claim: adding an audit engine is a new dependency that
// needs separate approval (docs/ui/p1.16-authentication-ux-contract.md, X4). It covers the rule classes axe
// rates serious/critical that can be decided from the live DOM and computed styles of one page state:
//
//   document-language / document-title / landmark-main / one-h1 / heading-order
//   control-name (buttons, links, inputs, selects, ARIA widgets) / label-for / duplicate-id / aria-reference
//   image-alt / aria-hidden-focusable / tabindex-positive
//   colour-contrast (WCAG 1.4.3 on resolved opaque backgrounds, 4.5:1, large text 3:1)
//   keyboard walk (every enabled control reachable by Tab; every stop has a visible focus indicator)
//
// What it cannot decide (screen-reader output, reading order semantics, background images, real
// password-manager behaviour, non-Chromium engines) is NOT covered and stays in the handoff as unverified.

/** Runs inside the page: returns the violations of one page state. */
function collectViolations() {
  const out = [];
  const add = (rule, impact, element, detail) => {
    const id = element.id ? `#${element.id}` : '';
    const label = (element.getAttribute?.('aria-label') ?? '').slice(0, 40);
    out.push({ rule, impact, node: `${element.tagName?.toLowerCase() ?? '?'}${id}${label ? `[${label}]` : ''}`, detail });
  };
  const visible = (el) => {
    for (let node = el; node && node.nodeType === Node.ELEMENT_NODE; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' || node.hasAttribute('hidden')) return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const hiddenFromAT = (el) => !!el.closest('[aria-hidden="true"]');
  const text = (el) => (el.textContent ?? '').replace(/\s+/g, ' ').trim();

  // Document level.
  if (!document.documentElement.getAttribute('lang')) add('document-language', 'serious', document.documentElement, 'no lang attribute');
  if (!document.title.trim()) add('document-title', 'serious', document.documentElement, 'empty title');
  const mains = Array.from(document.querySelectorAll('main, [role="main"]')).filter(visible);
  if (mains.length !== 1) add('landmark-main', 'moderate', document.body, `${mains.length} main landmarks`);
  const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6,[role="heading"]')).filter((h) => visible(h) && !hiddenFromAT(h));
  const levelOf = (h) => Number(h.getAttribute('aria-level') ?? (/^h([1-6])$/i.exec(h.tagName)?.[1] ?? 2));
  if (headings.filter((h) => levelOf(h) === 1).length !== 1) add('page-has-heading-one', 'moderate', document.body, `${headings.filter((h) => levelOf(h) === 1).length} level-1 headings`);
  let previous = 0;
  for (const heading of headings) {
    const level = levelOf(heading);
    if (previous && level > previous + 1) add('heading-order', 'moderate', heading, `h${previous} then h${level}`);
    if (!text(heading) && !heading.getAttribute('aria-label')) add('empty-heading', 'minor', heading, 'heading has no text');
    previous = level;
  }

  // Identifiers and references.
  const seen = new Map();
  for (const el of document.querySelectorAll('[id]')) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
  for (const [id, count] of seen) if (count > 1) add('duplicate-id', 'minor', document.getElementById(id), `id used ${count} times`);
  for (const el of document.querySelectorAll('[aria-labelledby],[aria-describedby],[aria-controls],[aria-owns],[for]')) {
    for (const attribute of ['aria-labelledby', 'aria-describedby', 'aria-controls', 'aria-owns', 'for']) {
      const value = el.getAttribute(attribute);
      if (!value) continue;
      // aria-controls may name something not rendered while collapsed; the others must resolve.
      if (attribute === 'aria-controls') continue;
      for (const ref of value.split(/\s+/)) if (!document.getElementById(ref)) add('aria-reference', 'critical', el, `${attribute} names a missing id`);
    }
  }

  // Names.
  const nameOf = (el) => {
    const labelledby = el.getAttribute('aria-labelledby');
    if (labelledby) {
      const joined = labelledby.split(/\s+/).map((id) => text(document.getElementById(id) ?? document.createElement('i'))).join(' ').trim();
      if (joined) return joined;
    }
    const label = (el.getAttribute('aria-label') ?? '').trim();
    if (label) return label;
    if (el.labels && el.labels.length) {
      const joined = Array.from(el.labels).map(text).join(' ').trim();
      if (joined) return joined;
    }
    if (el.tagName === 'INPUT' && ['button', 'submit', 'reset'].includes(el.type) && el.value) return el.value;
    if (el.tagName === 'IMG') return (el.getAttribute('alt') ?? '').trim();
    const own = text(el);
    if (own) return own;
    const title = (el.getAttribute('title') ?? '').trim();
    if (title) return title;
    const img = el.querySelector('img[alt]');
    return img ? (img.getAttribute('alt') ?? '').trim() : '';
  };
  const interactive = 'a[href],button,input:not([type="hidden"]),select,textarea,summary,[role="button"],[role="link"],[role="checkbox"],[role="radio"],[role="tab"],[role="switch"],[role="menuitem"],[tabindex]';
  const controls = Array.from(document.querySelectorAll(interactive)).filter((el) => visible(el));
  for (const el of controls) {
    if (el.tagName === 'DIV' && el.getAttribute('tabindex') === '-1' && !el.getAttribute('role')) continue; // programmatic focus target (panel/heading focus management)
    if (el.matches('[tabindex="-1"]:not(button,a,input,select,textarea)') && !el.getAttribute('role')) continue;
    // Hidden from assistive technology AND out of the tab order (the readOnly username hint that lets a password
    // manager associate a step-up password): nothing for a person to operate, so no name is required.
    if (hiddenFromAT(el) && el.getAttribute('tabindex') === '-1') continue;
    if (!nameOf(el)) add('control-name', 'critical', el, 'interactive element has no accessible name');
    if (Number(el.getAttribute('tabindex')) > 0) add('tabindex-positive', 'serious', el, 'positive tabindex');
    if (hiddenFromAT(el) && !el.disabled) add('aria-hidden-focusable', 'serious', el, 'focusable inside aria-hidden');
  }
  for (const el of document.querySelectorAll('img')) if (visible(el) && !el.hasAttribute('alt')) add('image-alt', 'critical', el, 'image without alt');
  for (const el of document.querySelectorAll('[role="img"]')) if (visible(el) && !nameOf(el)) add('role-img-alt', 'serious', el, 'role=img without a name');
  for (const el of document.querySelectorAll('input[type="checkbox"],input[type="radio"],input:not([type]),input[type="text"],input[type="password"],input[type="email"],input[type="tel"],input[type="search"],textarea,select')) {
    if (visible(el) && !el.disabled && !(hiddenFromAT(el) && el.getAttribute('tabindex') === '-1') && !nameOf(el)) add('label', 'critical', el, 'form control has no label');
  }

  // Colour contrast on resolved colours (opaque ancestors composited; background images are reported as unverifiable).
  const parse = (value) => {
    const m = /rgba?\(([^)]+)\)/.exec(value);
    if (!m) return null;
    const parts = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const over = (top, bottom) => {
    const a = top.a + bottom.a * (1 - top.a);
    if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
    return { r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / a, g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / a, b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / a, a };
  };
  const luminance = ({ r, g, b }) => {
    const channel = (c) => {
      const s = c / 255;
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  };
  const background = (el) => {
    const chain = [];
    for (let node = el; node && node.nodeType === Node.ELEMENT_NODE; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.backgroundImage && style.backgroundImage !== 'none') return null;
      const color = parse(style.backgroundColor);
      if (color && color.a > 0) chain.push(color);
      if (color && color.a === 1) break;
    }
    let result = { r: 255, g: 255, b: 255, a: 1 };
    if (document.documentElement && !chain.some((c) => c.a === 1)) {
      const root = parse(getComputedStyle(document.documentElement).backgroundColor);
      if (root && root.a > 0) result = over(root, result);
    }
    for (const color of chain.reverse()) result = over(color, result);
    return result;
  };
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const checked = new Set();
  let unverifiable = 0;
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const el = node.parentElement;
    if (!el || checked.has(el) || !node.textContent.trim() || !visible(el) || hiddenFromAT(el)) continue;
    checked.add(el);
    if (el.closest('[disabled],[aria-disabled="true"]')) continue;
    const style = getComputedStyle(el);
    const bg = background(el);
    const fg0 = parse(style.color);
    if (!bg || !fg0) {
      unverifiable += 1;
      continue;
    }
    const fg = over({ ...fg0, a: fg0.a }, bg);
    const l1 = luminance(fg);
    const l2 = luminance(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    const px = parseFloat(style.fontSize);
    const bold = Number(style.fontWeight) >= 700;
    const need = px >= 24 || (bold && px >= 18.66) ? 3 : 4.5;
    const rgb = (c) => `rgb(${Math.round(c.r)},${Math.round(c.g)},${Math.round(c.b)})`;
    if (ratio < need) add('color-contrast', 'serious', el, `contrast ${ratio.toFixed(2)}:1 < ${need}:1 (text ${rgb(fg)} on ${rgb(bg)}, class "${String(el.className).slice(0, 60)}", ${px}px)`);
  }
  return { violations: out, unverifiableContrast: unverifiable, controls: controls.length };
}

/** Walks the page with the real keyboard: every enabled control gets a stop with a visible focus indicator. */
async function keyboardWalk(page) {
  const expected = await page.evaluate(() => {
    const isVisible = (el) => {
      for (let node = el; node && node.nodeType === Node.ELEMENT_NODE; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden' || node.hasAttribute('hidden')) return false;
        // The content of a closed <details> (everything but its summary) is not rendered and cannot take focus.
        const parent = node.parentElement;
        if (parent && parent.tagName === 'DETAILS' && !parent.open && node.tagName !== 'SUMMARY') return false;
      }
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    };
    const candidates = Array.from(document.querySelectorAll('a[href],button,input:not([type="hidden"]),select,textarea,summary,[tabindex="0"]'))
      .filter((el) => !el.disabled && isVisible(el) && !el.closest('[inert]') && el.tabIndex >= 0);
    // A radio group is one tab stop: only its checked (or first) member is expected.
    const groups = new Map();
    const wanted = [];
    for (const el of candidates) {
      if (el.tagName === 'INPUT' && el.type === 'radio' && el.name) {
        if (!groups.has(el.name)) groups.set(el.name, []);
        groups.get(el.name).push(el);
      } else wanted.push(el);
    }
    for (const members of groups.values()) wanted.push(members.find((m) => m.checked) ?? members[0]);
    window.__a11yExpected = new Map(wanted.map((el, index) => [el, index]));
    window.__a11yGroups = groups;
    window.__a11yWanted = wanted;
    return wanted.map((el) => `${el.tagName.toLowerCase()}${el.type ? `[${el.type}]` : ''}${el.getAttribute('aria-label') ? `(${el.getAttribute('aria-label').slice(0, 30)})` : ''}`);
  });
  const problems = [];
  const reached = new Set();
  const trail = [];
  // Start from a known place: a focusable anchor before everything else. blur() alone leaves Firefox's
  // sequential-focus starting point where the previous click or focus was.
  await page.evaluate(() => {
    const anchor = document.createElement('span');
    anchor.id = '__a11y-anchor';
    anchor.tabIndex = -1;
    document.body.insertBefore(anchor, document.body.firstChild);
    anchor.focus();
    window.__a11yAnchor = anchor;
  });
  for (let i = 0; i < expected.length + 3; i += 1) {
    await page.keyboard.press('Tab');
    const stop = await page.evaluate(() => {
      const el = document.activeElement;
      if (!el || el === document.body || el === document.documentElement || el === window.__a11yAnchor) return null;
      const style = getComputedStyle(el);
      const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
      const shadow = style.boxShadow !== 'none';
      let index = window.__a11yExpected.get(el);
      if (index === undefined && el.tagName === 'INPUT' && el.type === 'radio') {
        const members = window.__a11yGroups.get(el.name) ?? [];
        index = members.length ? window.__a11yExpected.get(members.find((m) => m.checked) ?? members[0]) : undefined;
      }
      return { index: index ?? -1, indicator: outline || shadow, tag: el.tagName.toLowerCase() };
    });
    if (!stop) continue;
    if (!stop.indicator) problems.push({ rule: 'focus-visible', impact: 'serious', node: stop.tag, detail: 'keyboard focus has no visible indicator' });
    trail.push(String(stop.index));
    if (stop.index >= 0) reached.add(stop.index);
  }
  const states = await page.evaluate(() => window.__a11yWanted.map((el) => (el.isConnected ? (el.disabled ? 'disabled-now' : 'enabled') : 'replaced')));
  await page.evaluate(() => {
    if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
    window.__a11yAnchor?.remove();
    delete window.__a11yAnchor;
    delete window.__a11yExpected;
    delete window.__a11yGroups;
    delete window.__a11yWanted;
  });
  expected.forEach((name, index) => {
    if (!reached.has(index)) problems.push({ rule: 'keyboard-reach', impact: 'serious', node: name, detail: `enabled control is not reachable with Tab (${states.at(index)}; stops: ${trail.join(' ')})` });
  });
  return { problems, expected: expected.length, reached: reached.size };
}

/**
 * Audits one page state. Throws (naming the rule, impact and element, never page text) on any
 * violation. `label` is the step so a failure points at the state.
 */
export async function auditAccessibility(page, label) {
  // Audit a settled state: no request in flight (aria-busy) and two painted frames since the last change.
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'), undefined, { timeout: 10_000 });
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  // Colours are audited at rest: let CSS transitions (the 150 ms colour fades) finish first, so a restored page
  // is not judged mid-fade. Only finite transitions are awaited; the spinner animation is never waited on.
  await page.evaluate(() => Promise.all(document.getAnimations().filter((animation) => animation.transitionProperty !== undefined).map((animation) => animation.finished.catch(() => undefined))));
  const { violations, unverifiableContrast, controls } = await page.evaluate(collectViolations);
  const walk = await keyboardWalk(page);
  const all = [...violations, ...walk.problems];
  const blocking = all.filter((v) => v.impact === 'serious' || v.impact === 'critical' || v.impact === 'moderate');
  assert.deepEqual(blocking, [], `${label}: accessibility violations (${controls} controls, ${unverifiableContrast} contrast checks unverifiable)`);
  return { controls, tabStops: walk.reached, unverifiableContrast };
}

/** Test-only seam: the in-page rule set, for the audit's own detection test. */
export const _collectViolationsForTest = collectViolations;
