import { expect, test } from 'vitest';
import { IDENTIFIER_RULE, validateIdentifier } from './names';

test('letters, digits and . _ - @ + are accepted, starting with a letter or digit, up to 64 characters', () => {
  for (const ok of ['ada', 'Ada-2', 'ci.runner_1', 'sam@example.invalid', 'a+b', '9lives', 'x'.repeat(64)]) {
    expect(validateIdentifier(ok, 'username'), ok).toBeUndefined();
  }
});

test('an empty or blank value asks for the name', () => {
  expect(validateIdentifier('', 'username')).toBe('Enter the username.');
  expect(validateIdentifier('   ', 'group name')).toBe('Enter the group name.');
});

test('look-alike, control, space and over-long values are refused with the rule stated once', () => {
  for (const bad of ['ada lovelace', '-ada', '.ada', 'аda', 'ada\u202e', 'a\nb', 'a/b', 'x'.repeat(65), 'ada\u0000']) {
    expect(validateIdentifier(bad, 'username'), JSON.stringify(bad)).toBe(IDENTIFIER_RULE);
  }
});

test('surrounding whitespace is ignored, as it is when the value is sent', () => {
  expect(validateIdentifier('  ada  ', 'username')).toBeUndefined();
});
