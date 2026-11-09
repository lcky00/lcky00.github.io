---
layout: post
title: "SMB1 e NTLM: uno studio byte-per-byte del protocollo di autenticazione"
date: 2026-11-09
---

Negli ultimi mesi mi sono dedicato a uno studio approfondito di **SMB1** e di come al suo interno viaggia l'autenticazione **NTLM**. Non un'analisi "ad alto livello" presa da qualche slide, ma uno smontaggio byte per byte dei pacchetti scambiati tra client e server, fino a scrivere dei parser in **C** che li decodificano da zero.

Questo post mette insieme il lavoro fatto in diverse repo (gli appunti di studio, i parser e un server di validazione) in un unico percorso: da NetBIOS fino all'ultimo byte del blob NTLMSSP.

> Lo studio è nato per capire davvero come funziona l'autenticazione NTLM su SMB1, a livello di red teaming/offensive security e di didattica del protocollo. Tutto il codice è pensato per essere usato in ambienti autorizzati.

## 1. Il trasporto: NetBIOS e SMB

Prima di arrivare ai pacchetti SMB veri e propri, c'è da capire su cosa viaggiano. **NetBIOS** è un vecchio "modo" per far parlare tra loro i computer in una LAN, prima che DNS e TCP/IP diventassero lo standard. Forniva tre cose fondamentali:

1. **Un nome** al computer, risolto in broadcast sulla rete (non DNS).
2. **La possibilità di trovare altri host** tramite broadcast ("Chi si chiama PC-MARIO?" → "Sono io").
3. **Una sessione** sopra cui far viaggiare messaggi applicativi — ed è proprio sopra questa sessione che viaggia SMB.

Con l'arrivo di TCP/IP, Microsoft ha fatto girare NetBIOS sopra TCP/UDP, e oggi è sostanzialmente ridondante ma mantenuto per retrocompatibilità. Il risultato è che SMB oggi può viaggiare in due modi:

| Servizio | Porta | A cosa serve |
|---|---|---|
| NetBIOS Name | UDP 137 | Risoluzione nomi in broadcast |
| NetBIOS Datagram | UDP 138 | Messaggi broadcast/datagram |
| NetBIOS Session | TCP 139 | Trasporto SMB **dentro** NetBIOS |
| SMB diretto | TCP 445 | SMB **senza** NetBIOS |

Nel caso di **Direct TCP** (porta 445), ogni messaggio SMB è preceduto da un'intestazione di trasporto di 4 byte: il primo byte è sempre `0x00`, gli altri 3 indicano — in network byte order — la lunghezza del messaggio SMB che segue. È un dettaglio minimo ma fondamentale quando si scrive un parser: bisogna prima bufferizzare questi 4 byte, poi sapere quanti byte aspettarsi per il messaggio completo.

## 2. Il pacchetto SMB1

SMB1 (noto anche come **CIFS**) è un protocollo binario con struttura dinamica, diviso in tre blocchi:

- **`SMB_Header`**: 32 byte fissi, con `Protocol` (`\xFF SMB`), `Command`, `Status`, `Flags`/`Flags2` (qui c'è `SMB_FLAGS2_EXTENDED_SECURITY`, che segnala l'uso di NTLMSSP), `TID`, `PID`, `UID`, `MID`.
- **`SMB_Parameters`**: un `WordCount` (1 byte) seguito da un array di `Words`, con formato specifico per ogni comando.
- **`SMB_Data`**: un `ByteCount` (2 byte) seguito dai `Bytes` effettivi, anche qui specifici per comando.

I primi 4 byte di qualsiasi pacchetto SMB dicono subito con che versione si ha a che fare:

- `0xFF 'S' 'M' 'B'` → **SMB1**
- `0xFE 'S' 'M' 'B'` → **SMB2**

Una delle prime cose che un client fa, nel pacchetto `SMB_COM_NEGOTIATE` (`0x72`), è proporre una lista di **dialetti** supportati — stringhe come `PC NETWORK PROGRAM 1.0`, `LANMAN1.0`, fino a `NT LM 0.12`. Quest'ultimo è, di fatto, la "lingua franca" di SMB1 oggi: è il minimo comune denominatore che qualsiasi client Windows moderno (anche con SMB1 abilitato solo per retrocompatibilità) userà per negoziare con un server legacy. Il server risponde scegliendo un `DialectIndex` e, se negozia `NT LM 0.12`, nella risposta compare anche un campo cruciale: il **`SecurityBlob`**.

Ed è lì che inizia la parte interessante.

## 3. L'handshake NTLM sopra SMB1

Il flusso di autenticazione, nel caso tipico con **Extended Security** attiva, segue 5 passi:

1. **Negotiate Protocol Request** — il client propone i dialetti supportati.
2. **Negotiate Protocol Response** — il server sceglie `NT LM 0.12` e nel `SecurityBlob` propone i meccanismi di autenticazione supportati, codificati in **ASN.1** secondo lo schema **SPNEGO**.
3. **Session Setup AndX Request (`0x73`)** — il client risponde scegliendo il meccanismo (tipicamente NTLMSSP) e, nel campo `mechToken`, inserisce il primo pacchetto NTLM (`NTLMSSP_NEGOTIATE`, Type 1).
4. **Session Setup AndX Response (`0x73`)** — il server risponde con la challenge crittografica (`NTLMSSP_CHALLENGE`, Type 2).
5. **Session Setup AndX Request (`0x73`)** — il client chiude l'handshake inviando la risposta firmata alla challenge (`NTLMSSP_AUTH`, Type 3), che contiene — tra le altre cose — la **NTLMv2 response**.

Il contenuto del `SecurityBlob` resta lo stesso tra SMB1 e SMB2: cambia solo l'involucro SMB che lo trasporta. Il punto chiave è che dentro questo blob convivono **due mondi diversi**: una parte codificata in ASN.1 (GSSAPI/SPNEGO) e una parte che, a un certo punto, "esce" da ASN.1 ed è codificata secondo NTLMSSP, in little-endian.

## 4. ASN.1 DER: il linguaggio sotto SPNEGO

**ASN.1** è un linguaggio che descrive strutture dati, ma non dice come serializzarle in byte: per quello servono le **Encoding Rules**. Nel nostro caso, i blob di sicurezza SMB usano **DER** (Distinguished Encoding Rules), un sottoinsieme stretto di BER che garantisce una codifica unica e deterministica.

Il formato di trasferimento è sempre **TLV** (Tag, Length, Value):

```
+-------------------------------+
|   |   +---------------------+ |
|   |   |   |   +-----------+ | |
| T | L | T | L | T | L | V | | |
|   |   |   |   +-----------+ | |
|   |   +---------------------+ |
+-------------------------------+
```

- **Tag**: il tipo della struttura (classe + numero).
- **Length**: in forma breve se ≤ 127 byte (1 byte, bit più significativo a 0), in forma lunga se ≥ 128 byte (il bit più significativo a 1 indica quanti byte successivi codificano la lunghezza vera).
- **Value**: il contenuto — che a sua volta può essere un altro TLV, se il tipo è "constructed" (es. una `SEQUENCE`).

Alcuni tag ricorrenti nei blob SMB: `0x30` (SEQUENCE), `0x06` (OBJECT IDENTIFIER), `0x04` (OCTET STRING — il punto in cui, come vedremo, ASN.1 "muore" e inizia NTLMSSP).

Per esercitarmi su questo ho scritto **[asn1_parser](https://github.com/lcky00/asn1_parser)**, un parser DER minimale in C che costruisce un albero navigabile dei nodi, con tanto di logger per stampare la struttura annidata:

```c
asn1_tree_t tree;
asn1_parser_error_t res = parse(buffer, buffer_len, &tree);

if (res < PARSER_OK) {
    printf("Error: 0x%x\n", res);
    return 1;
}

dump_asn1_tree(tree);
asn1_tree_free(&tree);
```

## 5. Il modello a cipolla: GSSAPI → SPNEGO → NTLMSSP

Il modo più utile che ho trovato per visualizzare il `SecurityBlob` è come una matrioska a tre livelli:

![Modello a strati GSSAPI, SPNEGO, NTLMSSP](/assets/img/smb-ntlm-study/onion.png)

1. **GSSAPI (Initial Token)** — la "busta" standardizzata, in ASN.1 DER, che dice all'applicazione: *attenzione, questo è un token di negoziazione*.
2. **SPNEGO (`negTokenInit` / `negTokenResp`)** — anch'esso ASN.1 DER, contiene la lista dei meccanismi supportati (gli OID) e lo stato della negoziazione.
3. **Il payload del meccanismo scelto (NTLMSSP)** — da qui ASN.1 finisce: il payload è incapsulato in un **Octet String** (`0x04`), e da quel byte in poi si passa alle regole specifiche di NTLMSSP, in **little-endian**.

Perché serve SPNEGO? Perché client e server potrebbero supportare meccanismi diversi (Kerberos, NTLM...): **GSSAPI** fornisce l'interfaccia standard per gestire la sicurezza senza conoscere i dettagli del meccanismo specifico, mentre **SPNEGO** (RFC 4178) è lo "pseudo-meccanismo" che permette di negoziare in sicurezza quale meccanismo reale usare.

I due tipi di token SPNEGO principali sono:

- **`NegTokenInit`** (tag `0xa0`): propone i meccanismi (`mechTypes`), eventuali flag di contesto (`reqFlags`), un token "ottimistico" (`mechToken`) e un MIC per l'integrità.
- **`NegTokenResp`** (tag `0xa1`): comunica lo stato della negoziazione (`negState`: `accept-completed`, `accept-incomplete`, `reject`), il meccanismo scelto (`supportedMech`, solo nella prima risposta) e il payload vero e proprio (`responseToken`).

Per decodificare questo layer ho scritto **[spnego_decoder](https://github.com/lcky00/spnego_decoder)**, una libreria C **zero-copy**: prende in input l'albero ASN.1 già costruito da `asn1_parser` e, invece di ricopiare i byte, popola una struttura con puntatori diretti ai nodi dell'albero — compreso il payload NTLM interno, pronto per il passo successivo.

## 6. Dentro i blob: le 4 fasi byte per byte

Mettendo insieme quanto visto finora, ecco com'è fatto ciascuno dei 4 blob di sicurezza scambiati nell'handshake.

**Fase 1 — `SMB_COM_NEGOTIATE` Response.** Il server apre con l'header GSS-API (`0x60`), seguito dall'OID SPNEGO (`1.3.6.1.5.5.2`, codificato come `06 06 2b 06 01 05 05 02`), poi dalla `NegTokenInit` (`0xa0`) con la lista dei `mechTypes` supportati e, in `negHints` (`0xa3`), un'estensione Microsoft con il nome dell'host.

![Fase 1: SMB_COM_NEGOTIATE Response](/assets/img/smb-ntlm-study/blob1-negotiate.png)

**Fase 2 — `SMB_COM_SESSION_SETUP_ANDX` Request, NTLMSSP_NEGOTIATE.** Il client risponde con un `mechTypes` ridotto al solo OID scelto, e nel `mechToken` (`0xa2`) inserisce l'**Octet String** (`0x04`) che contiene il primo pacchetto NTLM vero e proprio, riconoscibile dalla firma `"NTLMSSP\0"` seguita dal Message Type `0x01000000` (NEGOTIATE) e dai flag di negoziazione.

![Fase 2: NTLMSSP_NEGOTIATE](/assets/img/smb-ntlm-study/blob2-ntlm-negotiate.png)

**Fase 3 — `SMB_COM_SESSION_SETUP_ANDX` Response, NTLMSSP_CHALLENGE.** Qui il tag cambia da `negTokenInit` a **`negTokenResp` (`0xa1`)**: l'header GSS-API (`0x60`) scompare perché il contesto è già stabilito. Dentro troviamo `negState` (`accept-incomplete`), `supportedMech` e `responseToken`, che contiene il pacchetto NTLM Type 2 con il **server challenge** (8 byte) e il **Target Info** con i dettagli del dominio/host del server.

![Fase 3: NTLMSSP_CHALLENGE](/assets/img/smb-ntlm-study/blob3-ntlm-challenge.png)

**Fase 4 — `SMB_COM_SESSION_SETUP_ANDX` Request, NTLMSSP_AUTH.** Il client chiude il giro con un `negTokenResp` contenente solo `responseToken`: al suo interno il pacchetto NTLM Type 3, con gli header per LM/NTLM Response, Domain, Username, Workstation, il **NTProofStr** (hash calcolato sulla challenge) e il **MIC**, seguiti dai valori effettivi delle stringhe ai rispettivi offset.

![Fase 4: NTLMSSP_AUTH](/assets/img/smb-ntlm-study/blob4-ntlm-auth.png)

Per parsare questo ultimo livello (il pacchetto NTLM vero e proprio) ho scritto **[ntlm_parser](https://github.com/lcky00/ntlm_parser)**, che gestisce i tre tipi di messaggio (`NEGOTIATE`, `CHALLENGE`, `AUTH`) ed espone in modo strutturato username, dominio, hostname e la **NTLMv2 Response** con i relativi AV Pair (`NetBIOS domain name`, `NetBIOS computer name`, `DNS domain name`, timestamp, ecc.).

## 7. Il parser SMB1 e la catena completa

A monte di tutto, ovviamente, serve un parser del pacchetto SMB1 in sé: **[smb1_parser](https://github.com/lcky00/smb1_parser)** è un parser difensivo, scritto per estrarre il `security_blob` esattamente dai due comandi che interessano per l'autenticazione NTLM: `SMB_COM_NEGOTIATE` (`0x72`) e `SMB_COM_SESSION_SETUP_ANDX` (`0x73`). È volutamente **limitato a questi due comandi** e alla variante con extended security (il `WordCount` lo determina): non è un'implementazione generica del protocollo, è uno strumento mirato.

Messi in fila, i quattro parser formano una catena a strati che rispecchia esattamente il modello a cipolla visto prima:

```
bytes SMB1 → smb1_parser → security_blob
                              │
                              ▼
                         asn1_parser → asn1_tree_t
                              │
                              ▼
                      spnego_decoder → mechToken / responseToken (zero-copy)
                              │
                              ▼
                        ntlm_parser → username, domain, hostname, NTLMv2 Response
```

Un dettaglio su cui vale la pena soffermarsi è la gestione della memoria: dato l'approccio **zero-copy** di `spnego_decoder` (i puntatori interni puntano dentro l'`asn1_tree_t`, non a copie), l'ordine di `free()` è obbligato — prima i dati applicativi (es. `free_ntlm_msg`), poi la struttura SPNEGO, e **solo per ultimo** l'albero ASN.1. Liberare l'albero troppo presto significa invalidare tutti i puntatori a valle, con conseguente *use-after-free*.

## 8. Mettere tutto insieme: un server di validazione

Per verificare che tutta la catena di parsing funzionasse correttamente contro un client reale (e non solo contro buffer statici nei test), ho scritto **[impostor](https://github.com/lcky00/impostor)**: un server SMB1 che implementa, lato server, lo stesso scambio visto sopra, come **macchina a stati**.

![Macchina a stati del server SMB1](/assets/img/smb-ntlm-study/impostor-state-machine.png)

| Stato | Transizione |
|---|---|
| 1. `NEGOTIATE` | Arriva un `SMB_COM_NEGOTIATE` → il server risponde e passa a `2. CHALLENGE` |
| 2. `CHALLENGE` | Arriva un `NTLMSSP_NEGOTIATE` → il server risponde con la challenge e passa a `3. AUTH` |
| 3. `AUTH` | Arriva un `NTLMSSP_AUTH` → il server completa lo scambio e torna a `1. NEGOTIATE` |

Ogni connessione client è tracciata da una struttura di stato (`client_t`) che, oltre allo stato corrente, mantiene un buffer RX (dati ricevuti ma non ancora processati) e un buffer TX con relativo offset (dati da inviare ma non ancora trasmessi del tutto), più i campi per ricostruire l'header NetBIOS a 4 byte.

Il main loop è basato su `poll()`, per gestire più connessioni contemporaneamente senza bloccarsi:

![Main loop di ricezione](/assets/img/smb-ntlm-study/impostor-main-loop.png)

L'idea alla base è semplice ma va gestita con attenzione: alla ricezione si verifica di avere almeno i 4 byte dell'header NetBIOS, si estrae la lunghezza del messaggio SMB atteso, si bufferizza finché il messaggio non è completo, e solo a quel punto lo si passa alla catena di parsing (`smb1_parser` → `asn1_parser` → `spnego_decoder` → `ntlm_parser`) facendo avanzare lo stato del client.

> `impostor` è pensato come strumento per attività di red teaming/offensive security autorizzate e per lo studio del protocollo SMB1/NTLM, da usare esclusivamente in ambienti di cui si ha il controllo o con consenso esplicito.

## Conclusioni

Quello che inizialmente era "voglio capire come funziona NTLM su SMB1" è diventato uno studio completo che tocca trasporto (NetBIOS), formati binari (SMB1), codifiche a oggetti (ASN.1 DER), negoziazione (SPNEGO) e infine il protocollo di autenticazione vero e proprio (NTLMSSP) — il tutto validato scrivendo i parser da zero in C e un server che li mette alla prova contro un client reale.

Le repo del progetto, se volete guardare il codice nel dettaglio:

- [smb1_parser](https://github.com/lcky00/smb1_parser) — parser del pacchetto SMB1
- [asn1_parser](https://github.com/lcky00/asn1_parser) — parser ASN.1 DER
- [spnego_decoder](https://github.com/lcky00/spnego_decoder) — decoder SPNEGO zero-copy
- [ntlm_parser](https://github.com/lcky00/ntlm_parser) — parser NTLMSSP
- [impostor](https://github.com/lcky00/impostor) — server SMB1 di validazione, a macchina a stati

Se avete domande o note su qualche passaggio, scrivetemi pure.
