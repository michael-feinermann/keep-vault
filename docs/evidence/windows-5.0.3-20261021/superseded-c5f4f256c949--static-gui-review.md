# Keep Vault 5.0.3: static WPF render review

Review recorded (UTC): 2026-10-21T18:46:04.5470941Z
Product visible in every image: Version 5.0.3. Each PNG is 1220 x 860 pixels at the test renderer's declared 96 DPI. Images were visually inspected using view_image; these are test-generated WPF RenderTargetBitmap images, not desktop screenshots.

## Findings

- ISSUE: Both extraction views render the visible Factor A input as a bright white, square-edged field (approximately x654-1145, y589 to viewport bottom). The other credential inputs use the dark rounded theme. FactorTextBox has replaced TextBox in the extraction XAML without an explicit shared style; implicit TextBox styling does not cover that derived control. Text entry and the scrolled Factor B field are not visually demonstrated by these images.
- REFERENCE COPY OBSERVATION (retained): Both creation views label the credential panel as decryption credentials and explain what is needed to extract an archive. This can be confusing in a creation flow, but source comparison confirms identical normative macOS wording in KeepVaultMac/Gui/MainWindow.Localization.cs, createPasswordTitle/createPasswordHelp. No copy change is proposed as part of the Windows styling correction.
- The DE/EN layouts, tabs, headings, password/PIN fields, language selector and visible buttons are otherwise legible, without an observed overlapping label in these samples. The create-help paragraphs and cryptographic-erasure limitations are readable. Content at the bottom of creation/extraction/erase viewports is clipped within a scrollable container; scrolling reachability and keyboard access were not exercised in this review.
- No separate settings/resource-controls view is present in this image set. The eight images comprise DE/EN create, extract, erase, and scrolled creation-help views. Only the language selector is visible as a preference control.

## Provenance and limits

The focused GUI log records PASS for gui.reference-render at 2026-10-21 18:39 UTC. The same focused batch had another GUI failure; its later targeted parity rerun passed separately. This visual review does not combine those runs into a new complete-suite PASS. The nonblank-render guard does not imply that every visual design detail is correct.
Current local product assembly: C:\Dev\Kalyna\KalynaArchiver\bin\Release\net10.0-windows\Keep Vault.dll
Product version: 5.0.3; last write UTC: 2026-10-21T18:38:22.5234484Z
Current local product assembly SHA-256: BCEB44732558DA8850C5A0DEFE0761A187237AB01EC811BEB74745702F71BCAA
The assembly metadata is a current observation, not an immutable final release binding or a claim that every image reflects later source edits.

No actual desktop launch, interaction, printing, paper output, camera scan, copy/paste, screen-capture protection success, installer workflow, other DPI/resolution, accessibility tooling or final signed release was verified by this review. The visible integrity and capture-protection labels show checking/enabling, not successful completion. Empty synthetic input fields were used.

## Reviewed image hashes

| Image | Bytes | Last write UTC | SHA-256 |
| --- | ---: | --- | --- |
| de-create-help.png | 185173 | 2026-10-21T18:39:01.5692941Z | D90AFB7EF9F00844EA2232F2992987717575B11E24CC880E9452FD95A8C253D1 |
| de-tab-1.png | 128174 | 2026-10-21T18:39:01.4838042Z | CC39B21E6D19CBB888DF38F109BD5FDF786223309FA19284B53278491D8DDA35 |
| de-tab-2.png | 159493 | 2026-10-21T18:39:01.5118134Z | 25992E9460F8E8E86B1B741D6D232881EFD58CB4E60FFA49D9DD2C24ECDE6689 |
| de-tab-3.png | 137408 | 2026-10-21T18:39:01.5353562Z | 8AFF3F5D391F79BFCBE91DD9A93B899EBE6A17008F18DC21A18EB9698C241EC3 |
| en-create-help.png | 162715 | 2026-10-21T18:39:01.4388013Z | AE8BBE3E57ABA093DB09405D4554FF10819DF284A0618424C2C9D3E0FF4BF8CF |
| en-tab-1.png | 113349 | 2026-10-21T18:39:01.3542641Z | 2B19EEBC3964C61600FBE4DCB09EB6AA35340E2075A0B78CAB16D57ED548F14D |
| en-tab-2.png | 143606 | 2026-10-21T18:39:01.3877793Z | 50E4FD3C435D00C9A86EE157328E2CBDAB71E7DCD900FBBE78BCFC2D0B55B4B2 |
| en-tab-3.png | 116336 | 2026-10-21T18:39:01.4132911Z | A1016F48D4C86F9553FA57D858D93E49D33EAEE242540A88CD39B8FF9A9AE667 |

Before-image originals preserved byte-for-byte under C:\Dev\Kalyna\work\windows-503-20261021\gui-render-before before the planned styling correction and rerender.

## After styling correction: observed result

Review recorded UTC: 2026-10-21T18:51:57.2653871Z
The new DE and EN extraction PNGs were separately reopened with view_image. In both, the visible Factor A field now has a dark background and rounded border consistent with the password/PIN controls. The previously observed white, square-edged field is corrected in these actual renders. The remainder of the visible extraction layout remains legible. The images still show only the top of Factor A; Factor B remains below the viewport. Its resolved style/template/colors are covered by the focused GUI regression, not by visual inspection of these two PNGs.

The corresponding style-build.log records successful managed build with 0 warnings and 0 errors. focused-gui2.log records all 5 GUI groups PASS, 0 FAIL, 0 BLOCKED, including gui.v502-reference-parity and gui.reference-render. This is a current focused GUI result, separate from the earlier failed GUI batch and from the pending complete release acceptance.

After-image source: C:\Dev\Kalyna\work\v502-gui-render
Preserved byte-identical copies of all eight new images: C:\Dev\Kalyna\work\windows-503-20261021\gui-render-after
Current observed product version: 5.0.3; product assembly last write UTC: 2026-10-21T18:49:59.0693539Z
Current product assembly SHA-256: B1DB7DE16DB2CB876273F3C6A844E21E8945168682BAF7FE1F2E5D311362B33C
style-build.log SHA-256: 8C211F132E2E990E806DE8431E7F173EC5F48F4DE500558887E04CC69FCB00BC
focused-gui2.log SHA-256: 6268D588957FF6D7349D1A5D8FF2F5A70128F73130C84DF93D76A6792E11FDF3

The previous limitations remain: test-generated static WPF output at 1220 x 860 / 96 DPI, empty synthetic fields, no actual desktop interaction or installation, no physical printing or camera scan, no proof of active capture protection or completed runtime integrity, and no final signed-release approval. No separate settings/resource view was added. The inherited macOS creation wording remains unchanged.

| After image | Bytes | Last write UTC | SHA-256 |
| --- | ---: | --- | --- |
| de-create-help.png | 185229 | 2026-10-21T18:50:18.3536917Z | FA23C783187EB9ECED2AC3A298349E19944C6125C5390F2414A7C212161079E9 |
| de-tab-1.png | 128227 | 2026-10-21T18:50:18.2701361Z | 1813232AF68DECA1E4F741EB7C3C5939C0FBE9325293A630880403A2EA752C13 |
| de-tab-2.png | 159784 | 2026-10-21T18:50:18.2971380Z | E3637C7F76DF09122D3729B5D6797AAA0A2F5F081459CE0251A58AE567D55F46 |
| de-tab-3.png | 137452 | 2026-10-21T18:50:18.3206578Z | 24FB0EC7B217FA41244691147ED940F824B22ED821A4FC105C0203B06128858B |
| en-create-help.png | 162738 | 2026-10-21T18:50:18.2247218Z | 143C886D3848D3251F408D9D830D322B79E7C6A25E5A657E94A435B905E4F757 |
| en-tab-1.png | 113372 | 2026-10-21T18:50:18.1408789Z | AAA04206BF7B0B2D225FB2AD9BB075DA8E9428F4AAE4EA5348CFCDBFEB5AF581 |
| en-tab-2.png | 143868 | 2026-10-21T18:50:18.1746672Z | AFD56D54D429375D08300A1E8775E2C576E1DC52FC422637D8FA904EF6A378E5 |
| en-tab-3.png | 116359 | 2026-10-21T18:50:18.1991803Z | A3911D7CDAA0A20E266E16A1E5DC09E99539345EA273503466560DBA60720683 |
