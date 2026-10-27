# Bounce samples

| File | Source |
|---|---|
| `postfix.eml` | Postfix 3.11.7 in `alpine:3`, 2026-10-27: a mail from `gate+b-abcdefghijklmnopqrstuvwxyz@example.test` to an unknown local user, bounced and delivered to `gate` - the mbox `From ` line removed |

Real bounces of other servers, such as Exchange Online, Outlook.com and Google, are collected in
[sisimai/set-of-emails](https://github.com/sisimai/set-of-emails). They stay out of this repository because they are
under the BSD 2-Clause License; the tests build their own variants in that form.
