// Progressive enhancement: without JavaScript all platform guidance stays visible.
const platformNav = document.querySelector(".platform-links");
if (platformNav) {
  const links = [...platformNav.querySelectorAll("a")];
  const panels = links.map((link) =>
    document.querySelector(link.getAttribute("href")),
  );
  platformNav.setAttribute("role", "tablist");
  function select(index, focus = false) {
    links.forEach((link, i) => {
      link.setAttribute("aria-selected", String(i === index));
      link.tabIndex = i === index ? 0 : -1;
      panels[i].hidden = i !== index;
    });
    if (focus) links[index].focus();
  }
  links.forEach((link, i) => {
    link.id = `platform-${panels[i].id}`;
    link.setAttribute("role", "tab");
    link.setAttribute("aria-controls", panels[i].id);
    panels[i].setAttribute("role", "tabpanel");
    panels[i].setAttribute("aria-labelledby", link.id);
    panels[i].tabIndex = 0;
    link.addEventListener("click", (event) => {
      event.preventDefault();
      select(i);
    });
    link.addEventListener("keydown", (event) => {
      const next = {
        ArrowRight: (i + 1) % links.length,
        ArrowLeft: (i + links.length - 1) % links.length,
        Home: 0,
        End: links.length - 1,
      }[event.key];
      if (next !== undefined) {
        event.preventDefault();
        select(next, true);
      }
    });
  });
  const fromHash = () => {
    const index = panels.findIndex((panel) => `#${panel.id}` === location.hash);
    if (index >= 0) select(index);
  };
  select(0);
  fromHash();
  window.addEventListener("hashchange", fromHash);
}
if (navigator.clipboard && window.isSecureContext) {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", async () => {
      const status = document.querySelector(".copy-status");
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
        status.textContent = "Command copied. Paste it into your terminal.";
      } catch {
        status.textContent =
          "Could not access the clipboard. Select and copy the command above.";
      }
    });
  });
}
