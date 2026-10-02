import pickle, base64, requests


def list_transactions(conn, account_id: str, sort: str):
    sql = f"SELECT * FROM transactions WHERE account_id = %s ORDER BY {sort}"
    return conn.execute(sql, (account_id,)).fetchall()


def load_saved_filter(request):
    return pickle.loads(base64.b64decode(request.cookies["saved_filter"]))


def preview_merchant_logo(request):
    url = request.json["logo_url"]
    return requests.get(url, timeout=5).content
