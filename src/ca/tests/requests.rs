/*  This file is part of Friends and Family CA.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
//! Certificate signing requests for RSA keys, which take too long to generate in each run.

/// `openssl req -new -nodes -subj /CN=backup -newkey rsa:1024`
pub const RSA_1024: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIIBUDCBugIBADARMQ8wDQYDVQQDDAZiYWNrdXAwgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBAMODST3/hyFPwMBS9OoTZSaVo5Vgt4HgdBA++oOJ2XS+fOqA+4+h
NUUeRe58+eTe47RyxO1WIJSMinRVbcenED3ou3pleazRnNxTmzroTKjR9UZBzGFU
3WVqy4+R8G4K2CW6JQomareEPPLciP5mHdh9Ogb4/7DKxYwmNen1MKDNAgMBAAGg
ADANBgkqhkiG9w0BAQsFAAOBgQDCSVXC9lLwnnqdWFoUxywJJ4uN4IaSdik204qu
QIJm7svMau6WZgZyFfHjNN1RG9h4jMbjSsO9sPIycUY4PeCFYlHMyYcdkPD2Q0Tt
j/LWKlr6ydmdGYC1R+xdbqC6KRu9R9oOV/M/fYwElJsN03fOdD822AyGimziMETN
0p32ug==
-----END CERTIFICATE REQUEST-----
";

/// `openssl req -new -nodes -subj /CN=backup -newkey rsa:2048`
pub const RSA_2048: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIICVjCCAT4CAQAwETEPMA0GA1UEAwwGYmFja3VwMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA1D2Dp03uuz++SU86XKY/ZIs6fXcAsQ1HyFrVt6+bL9p9
AtniumQUoXoNh0VyOtTA96yIC/rNImmdWmc2Sqboln3vUM9EJt5xBVuinCU1kkdq
MjZ7g/H/o/n+0vspBeqmKudLcRzgYALOqeT9u4a1bo2E1YihVg3SYaVkXRu7T352
9IZa/fQbmqT/NcEbQC0aihVlGdlsCax0LwLCVR8uS4X5ZxvNyPk+5MJc1+/hPlJy
/RIwLRO4Its2T1kgvEm+TXryWoNYktRlk+bG424eyI0U3RMExQu1adD4Z43NpN55
PTLWZ+bdx+Pnj6Ij/VGNcTHEjWnozHg0B8benLXWzwIDAQABoAAwDQYJKoZIhvcN
AQELBQADggEBABv5SvjwKl4fICo4Zl/yRUGu/ecDFYj4TWL/lV3Jxp1ReZCwfmCT
ypluwd3aX/dbflTBwTsWyk2LB7JfbO3zUopD3/2OODZa7HQfsb2UERIJCNL/c97p
TiIPIk0B2refivy0HOyVsDNK2FQKjHp1XKgKao5AH2qn1GUwm135OrdKH7bqrqNx
fGDHPa2xDeOd5HiNbAzgBxTcaLz0WnPcxvw6YBTP7984ltJ+vOMcO/raKok0aD5z
NOBBnvfkqBBI/VxevpoGaJyLFP936TJxC+hPhWOrK3s9daHTE+s6SYoyibh4fWgJ
wK72cfbu2jltDLHncZ4iaxmJfJWVjbY6obw=
-----END CERTIFICATE REQUEST-----
";
