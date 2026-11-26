# Email address book lookup and composition interface

Requirements for the local address book lookup and recipient selection interface used when composing emails.

## 1. Local autocomplete search engine

- **Trigger:** Activate when a user types into the `To`, `Cc`, or `Bcc` input fields.
- **Data source:** Query the local address book database (SQLite / Room).
- **Search fields:** Search simultaneously against both the Name field and the Email Address field.
- **Matching logic:** Use a case-insensitive, partial-match algorithm (for example, `LIKE '%query%'`).
- **Performance:** Debounce keystrokes by 150 ms to minimize database load. Limit dropdown results to the top 5 closest matches.

## 2. Autocomplete dropdown UI

- **Visual design:** Display matches in a floating dropdown below the active input line.
- **Content:** Show each contact's full name and email address, highlighting the matching characters.
- **Navigation:** Support keyboard navigation (Up/Down arrow keys to select, Enter/Tab to confirm, Escape to close).
- **Tokenization:** Upon selection, convert the text into a recipient pill/token containing the email address with a remove (`×`) button.

## 3. Address book search interface

- **Access point:** Provide a clickable directory/address book icon next to the address input fields.
- **Layout:** Open a dedicated modal or sheet featuring a top search bar and a scrollable list of results.
- **Actionable columns:** Show Name, Email, and Department with distinct `To`, `Cc`, and `Bcc` actions per contact.
- **Selection behavior:** Clicking an action immediately appends that contact's email as a token into the corresponding field of the active composition window.
- **Feedback:** Keep the picker open for multi-selection with a visual indicator (such as a checkmark) showing added contacts.

## 4. Edge cases and errors

- **No results found:** Display a subtle "No contacts found" message rather than an empty dropdown.
- **Duplicate prevention:** Ignore duplicate additions to the same recipient field and show a brief notification.
- **Invalid formats:** Allow users to enter custom email addresses not in the database when they match a valid email format.