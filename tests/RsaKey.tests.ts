/**
 * This file contains tests for the RsaKey.ts class.
 * 
 * @author Jacob Ian Matthews
 * @version 1.0 1/07/2020
 */

// Import the class
import { RsaKey } from "../mod.ts";

// Get a randomly generated RSA Key
const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBGO7lG+cxH3vnezGcboqjfF7RAYF293g7Hka/u4bVRxEnbrVS9
YfWCqGq/ta2VtqAi2vZTUJttMDkZg8+gx3+lKajlSLC+6ZlhI2IJrhij59sc99B/
9SOr32zeV5K4PfYMYHQ4jkLrzgxnuiYUDwSvtcUwcq6yiuEVHix+6kMD7KBVw23j
rO1t3CH+8g06EGVNs/o14lLaMGyysXMO+Ir/qvtQIMCYOfM60x9jbzg+OdnfC1oT
/783AwfpVWgg64Kf4EcGyhX9vXwqtSrIc/DRQxwIY+Kr2c9FwiVkaSfeHddl5Tkd
geZrPahzqBsoKRkjYYu+YKf6qqMHQzUe+QPtAgMBAAECggEAD0GR8ZT5hvMsm/US
wLIItM1VXlaQhlniI//Fk8J7vJNC5/Ey4yCQUB19cr9oQYk2J9wgfeCYopNDFAPJ
6kbrt1jhU00C97WOl8cz2J50w8XtltFN/T2mzgLuhy3GtTbgZ7fcBxz/9HEByNZq
xxisD+8QMoH26Nm6Ivg2+iqw+/0EVg3ggjcz9hYY1cUKlYsiw9lrrwVCfnWXbN7B
sfXAmP4FSxtpTa53sntbKgMGFaVoHbhxEXHRBOOT8SFzf1+J7McXIYarqB8T0bKx
3jhNlau9tYG17TNn7LYwv/+CSMNJnvQw5+v8vj9U9zQSwIR2BPl2gqw78MhOvo2T
Dhj6gQKBgQCMbQJVhx9RhlYzX9uyYTYlZKidJsAWSJzf/IlIpva1/QqKZIu7TEie
LYrK4LlC1BFcA4EXSS6x2jbqSfM8vZF6dOPSN4ejGdy4FNIBKy/nfWc1mR1VYd2m
Y8EyDsKZZ+4EjzdLCyX//Ca3DJLqh0Osx7zWn7KWjiKSXLgRLpO0uQKBgQCACYPD
sqiwBY2TfPVniEJ4nBNbLlWjuMbfvy5ONvXq5k+fS4ZEgPWfjfufb/g0aeEtT7KQ
TJlVdb8U1ZgIs+5UMUw6iPOFHDjhtPO23nevmFAUKPAsfYj6oSgN6NC9EU/u/rZG
woARsiCYhewVI/el4F030JYRekQHDEqEnonW1QKBgES6GVlYr4hL8iZktPbBwylb
8XYwf/SoBzdMtrf7F2YMeTswaH77n9LiwTn38FP3zKM3B9gothTPku7p0IUa1neT
e+jnypeV0cO6VOnDhEeMxZWi4YtnQX7s9aIVPUKtbf2HRm2RAEEf3KbcHY9xMjr+
6ro0IMi0udDeViv6msnpAoGAMGlolPpcphGzcmzxLXBsEcaR2wwt/XXEXJ2hGJnX
ajYjLQwVfJl2RhodZi+kHc1bAxL7ZWxRHesjkPEiR0gheVwagpd93HrLVyxgami7
wH1K6hSAm5Hr1ThSONAq/RIqsydELIUmf4pmoMUieuvam7G2DYCk/X7JchDHrFV1
sPECgYAsDYWGs0iMkQ2chyAdiyzaX1t7FnR2EYXnfx4wqsJACvzOx00yT1iozw2f
TxhCHtfXjf9MSSjQxms6fjGlqZdB6/Lk5m5UMdv8M+htBP6DiOSlhKTb3mvOd31g
IDjP3DH/Z76m52A3nY192r9QKNIbH04uvMGZ7b8vERUyALNduQ==
-----END RSA PRIVATE KEY-----`;

// Decode the key
const decoded = new RsaKey().decode(key);

// Console log the decoded key
console.log(decoded);
