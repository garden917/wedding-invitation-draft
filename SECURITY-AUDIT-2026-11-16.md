# 모청(모바일 청첩장) 보안 감사 결과 — 2026-11-16

대상: `work/wedding-invitation/index.html`, `work/wedding-invitation-draft`, Supabase `the-garden-2027` (`https://esltihjiljlucukpdsdj.supabase.co`), GitHub `garden917/wedding-invitation-draft`
기준: 개발자·보안담당자 관점(하객이 여는 실제 페이지)

## 결론

**프론트엔드 XSS는 0건입니다.** 방명록 이름·메시지, 모의고사 이름, RSVP, 계좌 표시까지 사용자 입력이 들어오는 곳은 모두 `esc()`( `& < > " '` 이스케이프)를 거치거나 `textContent`/`setAttribute`로만 들어가고, `eval`·`document.write`·`outerHTML`·`javascript:` URL·`setTimeout(문자열)`·인라인 `on*` 핸들러는 한 곳도 없습니다. 공격자 계좌로 번호를 바꿔치기하는 경로(스크립트 실행 → DOM 변조)는 실제 DB에 공격 페이로드를 넣고 라이브 페이지로 확인했을 때 **성립하지 않았습니다**(아래 3. 실측).

**DB는 읽기가 모두 막혀 있습니다.** anon 키로 `guestbook`(허용 5개 컬럼 외), `rsvp_responses`, `quiz_submissions`, `page_visits`, 관리용 뷰 2개를 읽으려 하면 전부 **401**이고, `PATCH`·`DELETE`도 전부 **401**입니다. 타인 이름·연락처 뒷자리·참석 여부·퀴즈 점수는 절대 내려오지 않습니다.

**남은 것은 코드 취약점이 아니라 구조적 위험입니다.** ① 정적 페이지 + 공개 anon 키라 누구나 DB에 직접 INSERT할 수 있음(스팸·무제한 길이·통계 오염), ② 쿠폰은 브라우저에서 생성돼 위조 가능, ③ 저장소가 공개라 그대로 복제한 피싱 페이지가 가능. 1번은 서버 제약(CHECK 길이) 추가로 상당 부분 막을 수 있어 아래 6절에 SQL을 적어 두었습니다.

---

## 1. 이번에 수정한 것

| 항목 | 내용 | 상태 |
|---|---|---|
| 주차 안내 문구 | `(자동 등록)` → **`(태블릿 셀프 등록)`** (index.html 1692행) | 로컬 반영·배포 |
| CSP(Content-Security-Policy) 메타 추가 | 외부 스크립트 차단 + 다른 서버로의 데이터 전송 차단. 허용: 이 페이지의 인라인 스크립트/스타일, Google Fonts, Supabase REST/RPC, `data:` 이미지 | 로컬 반영·배포 |

추가한 CSP:

```
default-src 'none'; script-src 'unsafe-inline';
style-src 'unsafe-inline' https://fonts.googleapis.com;
font-src https://fonts.gstatic.com; img-src 'self' data:;
media-src 'self'; connect-src https://esltihjiljlucukpdsdj.supabase.co;
base-uri 'none'; form-action 'none'
```

- `media-src 'self'`를 넣어 둔 이유: 나중에 인트로 mp4를 저장소에 올리면(`CONFIG.introVideo`) CSP 때문에 막히지 않게 하기 위해서입니다. YouTube 임베드로 바꾸면 `frame-src`를 추가해야 합니다.
- CSP로 막지 못하는 것: `frame-ancestors`(클릭재킹)는 meta로 지정할 수 없고 GitHub Pages는 헤더를 못 붙입니다. 인라인 스크립트를 허용(`'unsafe-inline'`)해야 하는 단일 파일 구조라, **인라인** 스크립트 주입까지는 막지 못합니다(= 지금 코드에 주입 지점이 없다는 점이 1차 방어). 대신 외부 스크립트 로드와 외부로의 데이터 유출은 막힙니다.

## 2. 프론트엔드 전수 점검

### 2-1. 위험한 API 사용처 (index.html 전체)

| API | 사용처 | 판정 |
|---|---|---|
| `innerHTML` | 2068(비우기), 2178·2195·2267(모의고사, 전부 `esc`), 2895·2955(방명록, 전부 `esc`), 3077·3079(도트 캐릭터 SVG, 숫자 인덱스만), 3293·3299(RSVP 완료 화면, `esc`), 3413(계좌, `esc`) | 안전 |
| `insertAdjacentHTML` | 2901 — 고정 문자열 `<span class="me-dot">` | 안전 |
| `outerHTML` / `document.write` | 없음 | — |
| `eval` / `new Function` / `Function(` | 없음 | — |
| `setTimeout("문자열")` / `setInterval("문자열")` | 없음(모두 함수 참조) | — |
| `href="javascript:…"` | 없음 | — |
| 인라인 `on*=` 핸들러 | 없음(라이브 DOM 실측 0개) | — |
| `<iframe>` / `<object>` / `<embed>` | 없음 | — |
| `fetch` 목적지 | Supabase REST/RPC + `CONFIG.guestbookEndpoint`(비어 있음) | 안전 |

- `esc()` 정의(1857행): `[&<>"']` 5종 이스케이프 → 텍스트 노드와 따옴표로 감싼 속성 모두 안전. `aria-label`·`data-copy`도 `esc` 또는 `setAttribute`라 속성 탈출 불가.
- 방명록 캐릭터(`avatar` jsonb)는 DB에서 무엇이 오든 `gbLook()`에서 0~N 정수로 클램프해 SVG 문자열을 만들기 때문에, SVG 마크업 주입 경로가 없습니다.
- `?ref=` 파라미터는 `[^0-9A-Za-z가-힣._-]` 제거 + 32자 제한 후 DB에만 쓰이고 화면에는 출력되지 않습니다.
- `localStorage` 복원값(모의고사 이름/연락처, RSVP 성함/메모, 방명록 이름/메시지)도 렌더링 시 모두 `esc`를 통과합니다.

### 2-2. 외부 의존성

- 외부에서 불러오는 것은 **Google Fonts CSS 1개**(fonts.googleapis.com)와 그 폰트 파일(fonts.gstatic.com)뿐입니다. JS 라이브러리·CDN·분석 도구 없음.
- 부작용: 방문자 IP·UA가 Google에 전달되고, 폰트 CDN이 막히면 시스템 폰트로 대체됩니다(레이아웃은 유지). 완전 자립을 원하면 폰트를 저장소에 넣고 `@font-face`로 바꾸면 됩니다(권고 사항, 이번엔 미적용).

### 2-3. 계좌번호 무결성

- 계좌 정보는 **외부 API/DB가 아니라 `index.html`의 `CONFIG.accounts`**(정적 데이터)에서만 옵니다. 현재 `{ groom: [], bride: [] }` — 즉 지금 화면에는 계좌번호가 아예 없고 "예식 전 업데이트 예정" 안내만 나옵니다.
- 나중에 값을 넣어도 `esc(r.bank)`, `esc(r.number)`, `esc(r.holder)`로만 렌더링되므로 마크업 주입은 불가합니다.
- 저장소 쓰기 권한: `garden917` 단독(admin)이며 collaborator는 본인 1명뿐입니다(확인: `gh api .../collaborators`). 다른 사람은 push 불가.
- 다만 저장소가 **PUBLIC**이라 누구나 코드를 복제해 "똑같이 생긴 가짜 청첩장"을 만들 수 있습니다(계좌번호만 바꿔치기). 이건 코드로 막을 수 없는 종류라, 하객에게는 항상 `garden917.github.io/...` 주소로만 공유하고 나중에 커스텀 도메인을 붙이는 것이 가장 확실합니다.

## 3. 실측 — 실제 DB에 공격 페이로드를 넣고 라이브 페이지로 확인

`guestbook`에 `<img src=x onerror=alert(1)>` / `<script>alert(document.cookie)</script>`를 anon 키로 INSERT(201)한 뒤, 라이브 페이지(https://garden917.github.io/wedding-invitation-draft/)를 실제 브라우저로 열어 확인:

- alert/confirm/prompt **실행 0회**, 페이지 런타임 에러 0건
- `img[src="x"]` 요소 0개, 인라인 `on*` 핸들러 0개, `<script>` 태그는 앱 자체 1개뿐
- 방명록 이름이 `<img src=x onerror=a…` 라는 **글자 그대로** 표시됨(텍스트 노드)
- `#acc`(마음 전하실 곳) 영역에 주입된 `img/script/iframe/object/embed` **0개**, 내용도 원래 안내 문구 그대로
- 검증 후 테스트 행은 **즉시 삭제**(아래 5절)

## 4. Supabase(`the-garden-2027`) 권한 실측 — anon(publishable) 키로 직접 호출

| 요청 | 결과 | 의미 |
|---|---|---|
| `GET /rest/v1/guestbook?select=*` | **401** `42501 permission denied` | 컬럼 지정 없이 전체 조회 불가 |
| `GET /rest/v1/guestbook?select=id,name,message,avatar,created_at` | 200 (허용 컬럼만) | 화면에 필요한 5개 컬럼만 공개 |
| `GET .../guestbook?select=visitor_id` / `ref_tag` | **401** | 방문자 식별자·유입 태그 노출 안 됨 |
| `GET .../guestbook?select=id&visitor_id=eq.…` / `order=visitor_id` | **401** | 필터·정렬로 값을 추정하는 우회도 차단 |
| `GET /rest/v1/rsvp_responses?select=*` | **401** | 타인 이름·연락처·참석 여부 조회 불가 |
| `GET /rest/v1/quiz_submissions?select=*` | **401** | 타인 점수·이름·연락처 조회 불가 |
| `GET /rest/v1/page_visits?select=*` | **401** | 방문 로그 조회 불가 |
| `GET /rest/v1/v_visitor_summary` · `v_ref_summary` | **401** | 관리자용 뷰 anon 차단 |
| `PATCH` / `DELETE` 4개 테이블 | **401** (전부) | 수정·삭제 권한 자체가 회수됨 |
| `GET /rest/v1/` (OpenAPI 스키마) | **401** | 테이블 목록 열람도 불가 |
| `POST /rest/v1/rsvp_responses` `attendance:"hacked"` | **400** `23514` CHECK 위반 | 참석값은 서버에서 화이트리스트 |
| `POST /rest/v1/rsvp_responses` `party_size:999` | **400** `23514` CHECK 위반 | 동행 인원 1~20 강제 |
| `POST /rest/v1/guestbook` (XSS 페이로드) | **201** | 쓰기는 열려 있음(설계상 필요) |
| `POST /rest/v1/guestbook` 이름·메시지 **5,000자** | **201** | **길이 제한 없음 — 아래 6절 참고** |
| `POST /rest/v1/quiz_submissions` `score:4, passed:true` 위조 | **201** | 만점·합격은 클라이언트 주장을 그대로 저장 |

- 주의: `guestbook`은 `avatar`(jsonb)가 NOT NULL입니다. 이 필드 없이 POST하면 400이 납니다(현재 코드는 항상 보냄).
- 위 실측에서 만든 테스트 행(guestbook 2 · quiz 1 · rsvp 1 · page_visits 1)은 전부 삭제했고, 최종 상태는 `guestbook 0 / rsvp 0 / quiz 1 / page_visits 3`입니다. 남은 1건(`ㅁㄴㅇ`, score 1, 16:28)과 방문 3건은 제가 만든 것이 아니라 기존 데이터라 손대지 않았습니다.

## 5. GitHub 저장소 감사

- 저장소: **PUBLIC**, Pages `main` 브랜치 루트, HTTPS 강제, `robots.txt` 전면 차단 + `<meta name="robots" content="noindex, nofollow, noarchive">`.
- 커밋 7개 전체 이력(`git log -p --all`) 검사: `service_role` **0**, `sb_secret` **0**, JWT(`eyJhbGciOi…`) **0**, `postgres://`·DB 비밀번호 **0**, 실명 연락처 **0**. 전화번호 패턴 2건은 모두 입력 예시 문구 `010-0000-0000`이었습니다.
- 공개되어 있는 것은 `sb_publishable_…`(anon) 키 하나 — 원래 공개되어도 되는 키이며, 실제 권한은 위 4절처럼 RLS/GRANT가 제한합니다. 실제 `service_role`·DB 비밀번호는 저장소에 없습니다.
- collaborator: `garden917` 1명(admin). invitations·branch protection API는 이 GitHub 연결 권한으로는 조회 불가(403)라 "다른 초대가 없다"까지는 확정하지 못했지만, collaborator 목록에는 본인만 있습니다.
- 커밋 작성자 이메일은 GitHub noreply 주소만 사용되고 개인 메일은 노출되지 않았습니다.

## 6. 남아 있는 구조적 위험과 대응

1. **익명 쓰기 = 스팸/오염 가능(가장 현실적인 위험).** anon 키가 공개되어 있으니 누구든 스크립트로 방명록 수천 건, 이름 5,000자, RSVP 위조 제출, `page_visits` 직접 INSERT(UV 통계 오염)를 할 수 있습니다. 지금은 서버 쪽 길이 제한이 없습니다.
   → 아래 SQL로 서버 제약을 추가하면 "폭주"는 막을 수 있습니다(무료 플랜에서 즉시 적용 가능, 대시보드 SQL Editor).
2. **선물 교환권 위조.** `coupon_code`는 브라우저에서 `Math.random`으로 만들고 `passed`도 클라이언트가 보냅니다. 화면을 조작해 만점 화면을 띄우는 것은 가능 → 접수처에서는 화면이 아니라 `quiz_submissions`의 해당 이름/뒷자리 `passed` 행이 있는지로 확인해야 합니다.
3. **공개 저장소 복제 피싱.** 위 2-3절.
4. **클릭재킹·MIME 스니핑 헤더 없음.** GitHub Pages는 보안 헤더를 못 붙입니다(HTTPS·HSTS는 붙음). 커스텀 도메인 + Cloudflare 프록시로 옮기면 `X-Frame-Options`, `Content-Security-Policy: frame-ancestors 'none'`까지 가능.
5. **Google Fonts 의존.** 프라이버시·가용성. 자체 호스팅 권고.
6. **방명록 300건 상한.** 첫 300건만 읽습니다(오래된 순). 하객이 300명을 넘게 남기면 최신 글이 다른 기기에 안 보임 → 필요해지면 `limit`을 올리거나 최신순 + 페이지네이션으로 바꿔야 합니다.
7. **하객 개인정보(이름·연락처 뒤4자리) 저장.** 읽기는 막혀 있지만 DB에는 쌓입니다. 예식 후 정리(삭제) 계획을 두는 것을 권합니다.

### 서버 제약 추가 SQL (권장, 직접 실행 전 확인)

```sql
-- 길이·형식 상한: 익명 대량/장문 입력으로 인한 오염 완화
alter table public.guestbook
  add constraint guestbook_name_len   check (char_length(name) between 1 and 20),
  add constraint guestbook_msg_len    check (char_length(message) between 1 and 200),
  add constraint guestbook_avatar_len check (pg_column_size(avatar) < 2048);

alter table public.rsvp_responses
  add constraint rsvp_name_len check (guest_name is null or char_length(guest_name) <= 20),
  add constraint rsvp_memo_len check (memo is null or char_length(memo) <= 200),
  add constraint rsvp_phone_len check (phone_last4 is null or phone_last4 ~ '^[0-9]{4}$'),
  add constraint rsvp_ref_len   check (ref_tag is null or char_length(ref_tag) <= 32);

alter table public.quiz_submissions
  add constraint quiz_name_len  check (name is null or char_length(name) <= 20),
  add constraint quiz_phone_len check (phone is null or char_length(phone) <= 8),
  add constraint quiz_score_rng check (score between 0 and 4);

alter table public.page_visits
  add constraint pv_ua_len check (user_agent is null or char_length(user_agent) <= 400);
```

- 기존 행이 제약을 위반하면 `ALTER TABLE`이 실패합니다(현재 guestbook·rsvp 0건, quiz 1건은 20자 이내라 통과 예상).
- 주의: 이미 들어온 위반 행이 있으면 먼저 정리해야 합니다. 적용 후에는 위조 시도가 400으로 떨어집니다.
- 이 SQL은 **적용하지 않았습니다.** 데이터 제약은 되돌리기 어렵고(제약 위반으로 정상 입력이 막힐 수 있음) 정원님이 판단할 부분이라, 실행 전 확인용으로 남겨 둡니다.

## 7. 재현 방법

```bash
# anon 키 권한 (읽기·수정·삭제 차단 확인)
K=sb_publishable_xfPcC7rcjNuglXNaWurCQQ_YR6otN20
U=https://esltihjiljlucukpdsdj.supabase.co
for t in guestbook rsvp_responses quiz_submissions page_visits v_visitor_summary v_ref_summary; do
  curl -s -o /dev/null -w "$t %{http_code}\n" -H "apikey: $K" -H "Authorization: Bearer $K" "$U/rest/v1/$t?select=*"
done

# 소스 내 위험 API 전수 검색
grep -n "innerHTML\|insertAdjacentHTML\|outerHTML\|document.write\|eval(\|new Function\|javascript:" work/wedding-invitation/index.html

# 커밋 이력 비밀정보 검색
cd work/wedding-invitation-draft && git log -p --all | grep -n "service_role\|sb_secret\|eyJhbGciOi\|postgres://"
```

`tools/security_audit.py`는 같은 검증을 브라우저에서 자동으로 돌리는 스크립트입니다(이 작업 환경에는 Chromium 라이브러리가 없어 실행하지 못했고, 대신 라이브 페이지 + 원격 브라우저로 같은 항목을 확인했습니다).
