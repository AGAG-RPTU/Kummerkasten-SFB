// UI strings in English and German. Elements carry data-i18n="key" (text) or
// data-i18n-html="key" (trusted markup from this file only); inputs may carry
// data-i18n-placeholder="key".

const STRINGS = {
  en: {
    'site.title': 'SFB-TRR 195 Kummerkasten',
    'site.short': 'Kummerkasten',
    'site.tagline': 'A confidential line to the trusted persons of the <a href="{sfbUrl}">SFB-TRR 195</a>',
    'nav.home': 'About',
    'nav.write': 'Write',
    'nav.open': 'My conversation',
    'lang.other': 'Deutsch',
    'footer.source': 'Source code',
    'footer.security': 'Security',
    'footer.staff': 'For trusted persons',
    'footer.imprint': 'Imprint',
    'footer.privacy': 'Privacy',
    'preview': '<strong>This is a preview!</strong> Do not use it for real confidential matters yet. The security review is still pending, and the trusted persons listed are for testing only.',

    'index.intro': '<p>Did something happen within the SFB that weighs on you: discrimination, harassment, a conflict, a problem you cannot solve alone? Or do you have a suggestion? Write to the trusted persons here, anonymously or with your name.</p>',
    'index.write': 'Write a message',
    'index.open': 'Continue a conversation',
    'index.how.title': 'How it works',
    'index.how.password': 'At the moment you also need the SFB access password. It is announced at SFB meetings and on the internal mailing lists. It only keeps out spam; it does not identify you.',
    'index.how.body': '<ol><li>Write your message. Name and contact details are optional. You need no account; while you write, your browser runs a short anti-spam check in the background.</li><li>After sending you get a <strong>codeword</strong> of six words. With it you can come back, read replies and answer. Keep it safe: nobody can recover it, not even the trusted persons.</li></ol>',
    'index.people.title': 'Who reads your message',
    'index.people.body': 'Only these persons can decrypt messages, and when writing you choose which of them receive yours. Each has a key; its fingerprint is shown so that it can be compared with the published source code.',
    'index.security.title': 'Privacy and security',
    'index.security.body': '<ul><li>Your message is encrypted in your browser before it is sent. The server stores only encrypted data. Only you (with the codeword) and the trusted persons you chose can read it.</li><li>The application stores no IP addresses. The web server’s access log may record them for a limited time.</li><li>The trusted persons are notified of new messages by email; these emails contain no message content, but they are sent at once, so they show when you wrote.</li><li>Times are stored rounded to the nearest hour; the length of a message is rounded up to 512 characters.</li><li>To hide even the fact that you visited this page, use the <a href="https://www.torproject.org/">Tor Browser</a>.</li><li>Whoever runs the server could deliver altered program code. Because the code is <a href="{sourceUrl}">open source</a>, anyone can check that the site delivers exactly the published version, though such a check shows only what the checker received. Trusted persons can avoid the risk by running the pages from their own verified copy. Details: <a href="{securityUrl}">security documentation</a>.</li></ul>',
    'index.fingerprint': 'Key fingerprint',
    'index.people.none': 'No trusted persons are registered yet.',

    'write.title': 'Write a message',
    'write.password': 'SFB access password',
    'write.passwordHint': 'The password announced to all SFB members; it only keeps out spam. You do not choose a secret here: your personal codeword for reading replies is created when you send.',
    'write.recipients': 'Who should read your message?',
    'write.recipientsHint': 'Only the persons you tick can read the message and learn that it exists. You can leave out anyone, for example someone your message is about.',
    'write.recipientsNone': 'Tick at least one person.',
    'write.category': 'Category',
    'cat.problem': 'Report a problem',
    'cat.feedback': 'Suggestion or feedback',
    'cat.question': 'Question',
    'cat.other': 'Other',
    'write.subject': 'Subject',
    'write.body': 'Your message',
    'write.optional': 'Optional: who you are',
    'write.optionalHint': 'Leave these empty to stay anonymous. They are encrypted like the message.',
    'write.name': 'Name',
    'write.contact': 'How to reach you (e.g. email)',
    'write.send': 'Encrypt and send',
    'pow.working': 'Anti-spam check running in the background while you write: {pct} %',
    'pow.done': 'Anti-spam check complete.',
    'pow.waiting': 'Finishing the anti-spam check…',
    'done.title': 'Sent. This is your codeword:',
    'done.earlier': 'An earlier attempt had already arrived, with the text as it was then. Open the conversation to check it. Add changes as a reply, or delete the conversation and write a new one.',
    'done.warn': 'Write it down or save it now. It is the only way to read replies, and it cannot be recovered. Keep it private: whoever has it can read the conversation.',
    'done.copy': 'Copy',
    'done.copied': 'Copied',
    'done.download': 'Save as text file',
    'done.confirm': 'I have saved my codeword.',
    'done.next': 'Go to the conversation',
    'done.file': 'SFB-TRR 195 Kummerkasten\n\nCodeword: {codeword}\n\nRead replies at {url}\n',
    'done.leave': 'You have not confirmed that you saved your codeword.',

    'conv.title': 'Your conversation',
    'conv.codeword': 'Codeword',
    'conv.hint': 'Six words, separated by spaces or dashes. The first three letters of each word are enough.',
    'conv.show': 'Show codeword',
    'time.approx': '{date}, around {hour}',
    'conv.open': 'Open',
    'conv.recognised': '{n} of {total} valid words recognised: {words}',
    'conv.unknown': 'Not valid: {words}',
    'words.recognisedCount': '{n} of {total} valid words recognised',
    'words.unknownCount': 'Words not valid: {n}',
    'conv.you': 'You',
    'conv.readers': 'Can read this conversation: {names}',
    'conv.noReply': 'No reply yet. The trusted persons usually answer within a few days; please check back later.',
    'conv.closed': 'The trusted persons marked this conversation as resolved. It will be deleted after some time unless you write again.',
    'conv.reply': 'Your reply',
    'conv.send': 'Send',
    'conv.delete': 'Delete conversation',
    'conv.deleteConfirm': 'Delete this conversation for everyone? This cannot be undone.',
    'conv.deleted': 'The conversation was deleted.',
    'conv.lock': 'Close',

    'staff.title': 'Trusted persons',
    'staff.who': 'Who are you?',
    'staff.passphrase': 'Passphrase',
    'staff.unlock': 'Log in',
    'staff.refresh': 'Refresh',
    'staff.none': 'No conversations yet. New messages appear here; you are also notified by email.',
    'staff.awaiting': 'awaiting reply',
    'staff.open': 'open',
    'staff.closed': 'resolved',
    'staff.close': 'Mark as resolved',
    'staff.requester': 'Requester',
    'staff.category': 'Category',
    'staff.name': 'Name',
    'staff.contact': 'Contact',
    'staff.noSubject': '(no subject)',
    'staff.lock': 'Log out',
    'staff.rekey.notice': '{n} conversation(s) are still encrypted for your previous key, probably from before you changed your passphrase. Enter your previous passphrase once to take them over.',
    'staff.rekey.label': 'Previous passphrase',
    'staff.rekey.submit': 'Take over',
    'staff.rekey.done': '{n} conversation(s) taken over; your current passphrase opens them now.',
    'staff.rekey.none': 'This passphrase opens none of these conversations.',
    'staff.alsoReads': 'Also readable by: {names}',
    'staff.onlyYou': 'Only you can read this conversation.',
    'staff.whoami': 'Logged in as {name} ({id}). Your key fingerprint: {fingerprint}',
    'staff.voteDelete': 'Vote to delete',
    'staff.unvoteDelete': 'Withdraw delete vote',
    'staff.deleteConfirm': 'Vote to delete this conversation? It is deleted for everyone once all trusted persons have voted. This cannot be undone.',
    'staff.deleteVotes': 'Delete votes: {voted}. Still needed: {missing}.',

    'setup.title': 'Create a key for a trusted person',
    'setup.intro': 'Do this once, on your own device. The passphrase never leaves this browser. Afterwards send the entry shown below to whoever maintains the site.',
    'setup.id': 'Short id: your first name in lowercase letters, e.g. erika',
    'setup.rotate': 'Changing your passphrase: create a new key here with your existing short id and send the entry. Once it has replaced your old one, log in with the new passphrase; the page then asks once for the previous one, to take over your conversations.',
    'setup.name': 'Display name',
    'setup.email': 'Email address for notifications',
    'setup.emailHint': 'New messages are announced here, without their content. The address is stored in the public keys.json, like your name.',
    'setup.generate': 'Generate passphrase',
    'setup.passphrase': 'Your passphrase. Copy it into your password manager now; it cannot be recovered.',
    'words.format': 'The words are separated by single spaces. When you enter it later, case and separators do not matter, and the first three letters of each word are enough.',
    'setup.copy': 'Copy passphrase',
    'setup.copyEntry': 'Copy entry',
    'setup.retype': 'Paste the passphrase from your password manager to confirm',
    'setup.create': 'Create key',
    'setup.result': 'Your entry for keys.json; send it to whoever maintains the site:',
    'setup.fingerprint': 'Fingerprint',
    'setup.fingerprintHint': 'A short checksum of your public key. It is not secret. The front page shows it next to your name, so that senders and you can check that the site encrypts for your key and not a swapped one. You need not save it: the trusted persons page shows it after you log in. If the front page ever shows a different one for you, tell the maintainer. You can also announce it in the SFB, so that others can compare.',

    'status.encrypting': 'Encrypting…',
    'status.deriving': 'Computing keys, this takes a moment…',
    'status.sending': 'Sending…',
    'status.loading': 'Loading…',

    'err.password': 'Wrong password.',
    'err.rate': 'Too many messages right now. Please try again in an hour.',
    'err.generic': 'Something went wrong: {msg}',
    'err.notConfigured': 'The Kummerkasten is not set up yet: no trusted persons are configured.',
    'err.empty': 'Please write a message.',
    'err.noRecipients': 'Choose at least one trusted person.',
    'err.codeword': 'A codeword has six words.',
    'err.notFound': 'No conversation for this codeword. Please check the words.',
    'err.passphrase': 'This passphrase does not belong to {name}.',
    'err.retype': 'The passphrases do not match.',
    'err.id': 'The id must start with a lowercase letter and contain only a–z, 0–9 and _.',
    'err.conflict': 'Someone wrote in the meantime. The conversation was reloaded; please send again.',
    'err.decrypt': '[This message could not be decrypted.]',
    'err.convFull': 'This conversation has reached its size limit. Please start a new one.',
    'err.storage': 'The Kummerkasten cannot take more messages right now. Please try again later.',
    'err.network': 'No answer from the server; the connection may have dropped. Please try again. Nothing will be sent twice.',
  },

  de: {
    'site.title': 'SFB-TRR 195 Kummerkasten',
    'site.short': 'Kummerkasten',
    'site.tagline': 'Ein vertraulicher Draht zu den Vertrauenspersonen des <a href="{sfbUrl}">SFB-TRR 195</a>',
    'nav.home': 'Info',
    'nav.write': 'Schreiben',
    'nav.open': 'Meine Unterhaltung',
    'lang.other': 'English',
    'footer.source': 'Quellcode',
    'footer.security': 'Sicherheit',
    'footer.staff': 'Für Vertrauenspersonen',
    'footer.imprint': 'Impressum',
    'footer.privacy': 'Datenschutz',
    'preview': '<strong>Dies ist eine Vorschau!</strong> Bitte noch nicht für echte vertrauliche Anliegen verwenden. Die Sicherheitsprüfung steht noch aus, und die eingetragenen Vertrauenspersonen dienen nur zum Testen.',

    'index.intro': '<p>Ist im SFB etwas passiert, das dich belastet: Diskriminierung, Belästigung, ein Konflikt, ein Problem, das du nicht allein lösen kannst? Oder hast du einen Vorschlag? Schreib den Vertrauenspersonen hier, anonym oder mit Namen.</p>',
    'index.write': 'Nachricht schreiben',
    'index.open': 'Unterhaltung fortsetzen',
    'index.how.title': 'So funktioniert es',
    'index.how.password': 'Derzeit brauchst du außerdem das SFB-Zugangspasswort. Es wird bei SFB-Treffen und auf den internen Mailinglisten bekanntgegeben. Es hält nur Spam fern und sagt nichts über dich.',
    'index.how.body': '<ol><li>Schreib deine Nachricht. Name und Kontaktdaten sind freiwillig. Du brauchst kein Konto; während du schreibst, führt dein Browser im Hintergrund eine kurze Spam-Prüfung durch.</li><li>Nach dem Absenden bekommst du ein <strong>Codewort</strong> aus sechs Wörtern. Damit kannst du wiederkommen, Antworten lesen und antworten. Bewahre es gut auf: Niemand kann es wiederherstellen, auch die Vertrauenspersonen nicht.</li></ol>',
    'index.people.title': 'Wer deine Nachricht liest',
    'index.people.body': 'Nur diese Personen können Nachrichten entschlüsseln, und beim Schreiben wählst du, welche von ihnen deine bekommen. Jede hat einen Schlüssel; sein Fingerabdruck steht hier, damit man ihn mit dem veröffentlichten Quellcode vergleichen kann.',
    'index.security.title': 'Datenschutz und Sicherheit',
    'index.security.body': '<ul><li>Deine Nachricht wird in deinem Browser verschlüsselt, bevor sie gesendet wird. Der Server speichert nur verschlüsselte Daten. Lesen können sie nur du (mit dem Codewort) und die Vertrauenspersonen, die du ausgewählt hast.</li><li>Die Anwendung speichert keine IP-Adressen. Das Zugriffsprotokoll des Webservers kann sie für begrenzte Zeit enthalten.</li><li>Die Vertrauenspersonen werden per E-Mail über neue Nachrichten benachrichtigt; diese E-Mails enthalten keinen Nachrichteninhalt, werden aber sofort verschickt und zeigen daher, wann du geschrieben hast.</li><li>Zeiten werden auf die nächste volle Stunde gerundet gespeichert; die Länge einer Nachricht wird auf 512 Zeichen aufgerundet.</li><li>Wenn auch niemand sehen soll, dass du diese Seite besucht hast, nutze den <a href="https://www.torproject.org/de/">Tor Browser</a>.</li><li>Wer den Server betreibt, könnte veränderten Programmcode ausliefern. Da der <a href="{sourceUrl}">Code offen</a> ist, kann jeder prüfen, ob die Seite genau die veröffentlichte Version ausliefert; eine solche Prüfung zeigt allerdings nur, was die prüfende Person erhalten hat. Vertrauenspersonen können das Risiko umgehen, indem sie die Seiten aus einer eigenen, geprüften Kopie laufen lassen. Details: <a href="{securityUrl}">Sicherheitsdokumentation</a> (englisch).</li></ul>',
    'index.fingerprint': 'Fingerabdruck des Schlüssels',
    'index.people.none': 'Es sind noch keine Vertrauenspersonen eingetragen.',

    'write.title': 'Nachricht schreiben',
    'write.password': 'SFB-Zugangspasswort',
    'write.passwordHint': 'Das Passwort, das allen SFB-Mitgliedern bekanntgegeben wird; es hält nur Spam fern. Hier wählst du kein Geheimnis: Dein persönliches Codewort zum Lesen der Antworten wird beim Absenden erzeugt.',
    'write.recipients': 'Wer soll deine Nachricht lesen?',
    'write.recipientsHint': 'Nur die angekreuzten Personen können die Nachricht lesen und erfahren überhaupt von ihr. Du kannst jede Person weglassen, zum Beispiel jemanden, um den es in deiner Nachricht geht.',
    'write.recipientsNone': 'Kreuze mindestens eine Person an.',
    'write.category': 'Kategorie',
    'cat.problem': 'Problem melden',
    'cat.feedback': 'Vorschlag oder Rückmeldung',
    'cat.question': 'Frage',
    'cat.other': 'Sonstiges',
    'write.subject': 'Betreff',
    'write.body': 'Deine Nachricht',
    'write.optional': 'Freiwillig: wer du bist',
    'write.optionalHint': 'Leer lassen, um anonym zu bleiben. Diese Angaben werden wie die Nachricht verschlüsselt.',
    'write.name': 'Name',
    'write.contact': 'Wie wir dich erreichen (z. B. E-Mail)',
    'write.send': 'Verschlüsseln und senden',
    'pow.working': 'Spam-Schutz läuft im Hintergrund, während du schreibst: {pct} %',
    'pow.done': 'Spam-Schutz abgeschlossen.',
    'pow.waiting': 'Spam-Schutz wird abgeschlossen…',
    'done.title': 'Gesendet. Das ist dein Codewort:',
    'done.earlier': 'Ein früherer Versuch war bereits angekommen, mit dem damaligen Text. Öffne die Unterhaltung, um ihn zu prüfen. Ergänze Änderungen als Antwort, oder lösche die Unterhaltung und schreib eine neue.',
    'done.warn': 'Schreib es jetzt auf oder speichere es. Nur damit kannst du Antworten lesen, und es lässt sich nicht wiederherstellen. Halte es geheim: Wer es hat, kann die Unterhaltung lesen.',
    'done.copy': 'Kopieren',
    'done.copied': 'Kopiert',
    'done.download': 'Als Textdatei speichern',
    'done.confirm': 'Ich habe mein Codewort gespeichert.',
    'done.next': 'Zur Unterhaltung',
    'done.file': 'SFB-TRR 195 Kummerkasten\n\nCodewort: {codeword}\n\nAntworten lesen unter {url}\n',
    'done.leave': 'Du hast noch nicht bestätigt, dass du dein Codewort gespeichert hast.',

    'conv.title': 'Deine Unterhaltung',
    'conv.codeword': 'Codewort',
    'conv.hint': 'Sechs Wörter, getrennt durch Leerzeichen oder Bindestriche. Die ersten drei Buchstaben jedes Worts genügen.',
    'conv.show': 'Codewort anzeigen',
    'time.approx': '{date}, ca. {hour}',
    'conv.open': 'Öffnen',
    'conv.recognised': '{n} von {total} gültigen Wörtern erkannt: {words}',
    'conv.unknown': 'Ungültig: {words}',
    'words.recognisedCount': '{n} von {total} gültigen Wörtern erkannt',
    'words.unknownCount': 'Ungültige Wörter: {n}',
    'conv.you': 'Du',
    'conv.readers': 'Diese Unterhaltung lesen können: {names}',
    'conv.noReply': 'Noch keine Antwort. Die Vertrauenspersonen antworten meist innerhalb weniger Tage; schau später wieder vorbei.',
    'conv.closed': 'Die Vertrauenspersonen haben diese Unterhaltung als erledigt markiert. Sie wird nach einiger Zeit gelöscht, wenn du nicht erneut schreibst.',
    'conv.reply': 'Deine Antwort',
    'conv.send': 'Senden',
    'conv.delete': 'Unterhaltung löschen',
    'conv.deleteConfirm': 'Diese Unterhaltung für alle löschen? Das lässt sich nicht rückgängig machen.',
    'conv.deleted': 'Die Unterhaltung wurde gelöscht.',
    'conv.lock': 'Schließen',

    'staff.title': 'Vertrauenspersonen',
    'staff.who': 'Wer bist du?',
    'staff.passphrase': 'Passphrase',
    'staff.unlock': 'Anmelden',
    'staff.refresh': 'Aktualisieren',
    'staff.none': 'Noch keine Unterhaltungen. Neue Nachrichten erscheinen hier; zusätzlich kommt eine Benachrichtigung per E-Mail.',
    'staff.awaiting': 'wartet auf Antwort',
    'staff.open': 'offen',
    'staff.closed': 'erledigt',
    'staff.close': 'Als erledigt markieren',
    'staff.requester': 'Anfragende Person',
    'staff.category': 'Kategorie',
    'staff.name': 'Name',
    'staff.contact': 'Kontakt',
    'staff.noSubject': '(kein Betreff)',
    'staff.lock': 'Abmelden',
    'staff.rekey.notice': '{n} Unterhaltung(en) sind noch für deinen früheren Schlüssel verschlüsselt, vermutlich von vor deinem Passphrasenwechsel. Gib einmalig deine frühere Passphrase ein, um sie zu übernehmen.',
    'staff.rekey.label': 'Frühere Passphrase',
    'staff.rekey.submit': 'Übernehmen',
    'staff.rekey.done': '{n} Unterhaltung(en) übernommen; deine aktuelle Passphrase öffnet sie jetzt.',
    'staff.rekey.none': 'Diese Passphrase öffnet keine dieser Unterhaltungen.',
    'staff.whoami': 'Angemeldet als {name} ({id}). Fingerabdruck deines Schlüssels: {fingerprint}',
    'staff.alsoReads': 'Außerdem lesen: {names}',
    'staff.onlyYou': 'Nur du kannst diese Unterhaltung lesen.',
    'staff.voteDelete': 'Für Löschen stimmen',
    'staff.unvoteDelete': 'Löschstimme zurückziehen',
    'staff.deleteConfirm': 'Für das Löschen dieser Unterhaltung stimmen? Sie wird für alle gelöscht, sobald alle Vertrauenspersonen zugestimmt haben. Das lässt sich nicht rückgängig machen.',
    'staff.deleteVotes': 'Löschstimmen: {voted}. Es fehlen noch: {missing}.',

    'setup.title': 'Schlüssel für eine Vertrauensperson erzeugen',
    'setup.intro': 'Einmalig auf dem eigenen Gerät durchführen. Die Passphrase verlässt diesen Browser nicht. Danach den angezeigten Eintrag an die Person schicken, die die Seite betreut.',
    'setup.id': 'Kurzname: dein Vorname in Kleinbuchstaben, z. B. erika',
    'setup.rotate': 'Passphrase wechseln: Erzeuge hier einen neuen Schlüssel mit deinem bisherigen Kurznamen und schick den Eintrag. Sobald er deinen alten ersetzt hat, melde dich mit der neuen Passphrase an; die Seite fragt dann einmal nach der früheren, um deine Unterhaltungen zu übernehmen.',
    'setup.name': 'Angezeigter Name',
    'setup.email': 'E-Mail-Adresse für Benachrichtigungen',
    'setup.emailHint': 'Neue Nachrichten werden hier angekündigt, ohne ihren Inhalt. Die Adresse steht wie dein Name in der öffentlichen keys.json.',
    'setup.generate': 'Passphrase erzeugen',
    'setup.passphrase': 'Deine Passphrase. Kopiere sie jetzt in deinen Passwortmanager; sie lässt sich nicht wiederherstellen.',
    'words.format': 'Die Wörter sind durch einzelne Leerzeichen getrennt. Bei der späteren Eingabe spielen Groß- und Kleinschreibung und Trennzeichen keine Rolle, und die ersten drei Buchstaben jedes Worts genügen.',
    'setup.copy': 'Passphrase kopieren',
    'setup.copyEntry': 'Eintrag kopieren',
    'setup.retype': 'Passphrase zur Bestätigung aus dem Passwortmanager einfügen',
    'setup.create': 'Schlüssel erzeugen',
    'setup.result': 'Dein Eintrag für keys.json; schick ihn an die Person, die die Seite betreut:',
    'setup.fingerprint': 'Fingerabdruck',
    'setup.fingerprintHint': 'Eine kurze Prüfsumme deines öffentlichen Schlüssels. Sie ist nicht geheim. Die Startseite zeigt sie neben deinem Namen, damit Absender und du prüfen können, dass die Seite für deinen Schlüssel verschlüsselt und nicht für einen untergeschobenen. Du musst sie nicht speichern: Die Seite für Vertrauenspersonen zeigt sie nach der Anmeldung an. Falls die Startseite für dich einmal einen anderen zeigt, sag der Person Bescheid, die die Seite betreut. Du kannst ihn auch im SFB bekanntgeben, damit andere vergleichen können.',

    'status.encrypting': 'Verschlüssele…',
    'status.deriving': 'Berechne Schlüssel, das dauert einen Moment…',
    'status.sending': 'Sende…',
    'status.loading': 'Lade…',

    'err.password': 'Falsches Passwort.',
    'err.rate': 'Gerade gibt es zu viele Nachrichten. Bitte in einer Stunde erneut versuchen.',
    'err.generic': 'Etwas ist schiefgegangen: {msg}',
    'err.notConfigured': 'Der Kummerkasten ist noch nicht eingerichtet: Es sind keine Vertrauenspersonen hinterlegt.',
    'err.empty': 'Bitte schreib eine Nachricht.',
    'err.noRecipients': 'Wähle mindestens eine Vertrauensperson.',
    'err.codeword': 'Ein Codewort hat sechs Wörter.',
    'err.notFound': 'Zu diesem Codewort gibt es keine Unterhaltung. Bitte prüfe die Wörter.',
    'err.passphrase': 'Diese Passphrase gehört nicht zu {name}.',
    'err.retype': 'Die Passphrasen stimmen nicht überein.',
    'err.id': 'Der Kurzname muss mit einem Kleinbuchstaben beginnen und darf nur a–z, 0–9 und _ enthalten.',
    'err.conflict': 'Inzwischen hat jemand geschrieben. Die Unterhaltung wurde neu geladen; bitte erneut senden.',
    'err.decrypt': '[Diese Nachricht konnte nicht entschlüsselt werden.]',
    'err.convFull': 'Diese Unterhaltung hat ihre Größengrenze erreicht. Bitte beginne eine neue.',
    'err.storage': 'Der Kummerkasten kann gerade keine weiteren Nachrichten aufnehmen. Bitte später erneut versuchen.',
    'err.network': 'Keine Antwort vom Server; vielleicht ist die Verbindung abgebrochen. Bitte erneut versuchen. Es wird nichts doppelt gesendet.',
  },
};

const LANG_KEY = 'kk-lang';
let lang = initialLang();

function initialLang() {
  try {
    const stored = localStorage.getItem(LANG_KEY);
    if (stored in STRINGS) {
      return stored;
    }
  } catch {
    // storage unavailable (private mode); fall through
  }
  return navigator.language?.startsWith('de') ? 'de' : 'en';
}

export function currentLang() {
  return lang;
}

// Placeholders every string may use, e.g. {sourceUrl}; set by site.js.
const globals = {};

export function setGlobals(values) {
  Object.assign(globals, values);
}

export function t(key, vars = {}) {
  const text = STRINGS[lang][key] ?? STRINGS.en[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (_, name) => vars[name] ?? globals[name] ?? '');
}

// Stored times are rounded to the nearest hour, so say "around 2 PM"
// rather than show a false minute.
export function formatTime(unixSeconds, { locale = lang, timeZone } = {}) {
  const time = new Date(unixSeconds * 1000);
  const date = time.toLocaleDateString(locale, { year: 'numeric', month: 'short', day: 'numeric', timeZone });
  const hour = time.toLocaleTimeString(locale, { hour: 'numeric', timeZone });
  return STRINGS[locale]['time.approx'].replace('{date}', date).replace('{hour}', hour);
}

const listeners = [];

// Callback runs after every language switch, for content rendered from JS.
export function onLanguageChange(fn) {
  listeners.push(fn);
}

export function applyI18n(root = document) {
  document.documentElement.lang = lang;
  for (const el of root.querySelectorAll('[data-i18n]')) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of root.querySelectorAll('[data-i18n-html]')) {
    el.innerHTML = t(el.dataset.i18nHtml);
  }
  for (const el of root.querySelectorAll('[data-i18n-placeholder]')) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  // Long texts such as the legal pages come as one block per language.
  for (const el of root.querySelectorAll('[data-lang]')) {
    el.hidden = el.dataset.lang !== lang;
  }
}

export function toggleLang() {
  setLang(lang === 'en' ? 'de' : 'en');
}

function setLang(next) {
  lang = next;
  try {
    localStorage.setItem(LANG_KEY, lang);
  } catch {
    // not remembered; fine
  }
  applyI18n();
  listeners.forEach((fn) => fn());
}
