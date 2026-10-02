from flask import Flask, jsonify, request, send_file
import os

app = Flask(__name__)
STATEMENTS_DIR = "/srv/statements"


@app.get("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    return jsonify(invoice.to_dict())


@app.get("/api/statements/download")
@login_required
def download_statement():
    name = request.args["file"]
    return send_file(os.path.join(STATEMENTS_DIR, name))
