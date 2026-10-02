public class StatementService {

    public List<Txn> findByMerchant(Connection conn, String accountId, String merchant) throws SQLException {
        String sql = "SELECT * FROM txns WHERE account_id = '" + accountId + "' AND merchant LIKE '%" + merchant + "%'";
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return map(rs);
        }
    }

    public Document parseBankFile(InputStream xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(xml);
    }

    private static final Logger log = LoggerFactory.getLogger(StatementService.class);

    public void logUpload(String bank, String fileName, String firstLine) {
        log.info("upload from {} file {} first line {}", bank, fileName, firstLine);
    }
}
