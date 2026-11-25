// Fake-credential shapes are ASSEMBLED AT RUNTIME so no complete "user:password" / "scheme://user:pw@host"
// literal exists in source (public repo; secret scanners match literals). Values are obviously fake.
export const up = (user, pw) => [user, pw].join(":");
export const urlWith = (scheme, user, pw, rest) => `${scheme}://${up(user, pw)}@${rest}`;
