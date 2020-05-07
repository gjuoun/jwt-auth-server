"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const pg_1 = require("pg");
const logger_1 = __importStar(require("../logger"));
const logger = logger_1.default.getConsoleLogger("db", logger_1.LOGGING_LEVEL.INFO);
exports.dbLogger = logger;
const client = new pg_1.Client({
    host: 'localhost',
    database: 'postgres',
    user: 'postgres',
    password: '21346687',
    port: 5432,
});
exports.db = client;
client.connect((err) => {
    if (err) {
        logger.error(err.message);
    }
    logger.info('connected to DB');
});
client.on("error", (err) => {
    logger.error(err.message);
});
//# sourceMappingURL=db.index.js.map