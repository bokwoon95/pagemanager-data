"use strict";

document.addEventListener("DOMContentLoaded", function main() {
  let deleteMode = false;
  pmToolbar();
  for (const node of document.querySelectorAll("[data-pm\\.key],[data-pm\\.row\\.key],[data-pm\\.row\\.href]")) {
    pmContenteditable(node);
  }
  for (const img of document.querySelectorAll("img[data-pm\\.img\\.upload]")) {
    pmImagePicker(img);
  }
  for (const node of document.querySelectorAll("[data-pm\\.row]")) {
    node.addEventListener("mouseenter", hoverdel(node));
  }
  for (const node of document.querySelectorAll("[data-pm\\.template]")) {
    const templateSelector = node.getAttribute("data-pm.template");
    const insertSelector = node.getAttribute("data-pm.insertafter");
    const template = document.querySelector(`#${templateSelector}`);
    const insertPoint = document.querySelector(`#${insertSelector}`);
    template.setAttribute("hidden", "true");
    insertPoint.setAttribute("hidden", "true");
    node.addEventListener("click", function () {
      const newNode = template.cloneNode(true);
      newNode.removeAttribute("id");
      newNode.removeAttribute("hidden");
      newNode.addEventListener("mouseenter", hoverdel(newNode));
      insertPoint.parentNode.insertBefore(newNode, insertPoint.nextSibling);
    });
  }

  function hoverdel(node) {
    return function () {
      if (!deleteMode) {
        return;
      }
      const rect = node.getBoundingClientRect();
      const overlay = pmCreateElement("div", {
        id: "pm-delete-overlay",
        style: {
          position: "absolute",
          content: "",
          height: `${rect.height}px`,
          width: `${rect.width}px`,
          top: `${rect.top + window.pageYOffset}px`,
          right: `${rect.right + window.pageXOffset}px`,
          bottom: `${rect.bottom}px`,
          left: `${rect.left}px`,
          "background-color": "hsl(0, 100%, 50%, 0.5)",
        },
      });
      document.querySelectorAll("#pm-delete-overlay").forEach((overlay) => overlay.remove());
      document.body.append(overlay);
      overlay.addEventListener("mouseout", function () {
        overlay.remove();
      });
      overlay.addEventListener("mousedown", function (event) {
        event.stopPropagation();
        node.remove();
        overlay.remove();
      });
    };
  }

  /**
   * pmCreateElement is a helper function wrapper around document.createElement().
   * It allows you to additionally specify the element's attributes and children
   * when creating the element.
   *
   * @param {string} tag
   * @param {object} attributes
   * @param {...HTMLElement} children
   */
  function pmCreateElement(tag, attributes, ...children) {
    if (tag.includes("<") && tag.includes(">") && attributes === undefined && children.length === 0) {
      const template = document.createElement("template");
      template.innerHTML = tag;
      return template.content;
    }
    const element = document.createElement(tag);
    for (const [attribute, value] of Object.entries(attributes || {})) {
      if (attribute === "style") {
        Object.assign(element.style, value);
        continue;
      }
      if (attribute.startsWith("on")) {
        element.addEventListener(attribute.slice(2), value);
        continue;
      }
      element.setAttribute(attribute, value);
    }
    element.append(...children);
    return element;
  }

  function pmToolbar() {
    const buttonAttributes = function (attributes) {
      return Object.assign({ class: "pm-toolbar-button" }, attributes);
    };
    const labelAttributes = { class: "pm-toolbar-button-label" };
    const deleteButton = pmCreateElement(
      "button",
      buttonAttributes({ title: "delete element under caret", onclick: deleteElement }),
      "Delete",
    );
    const toolbar = pmCreateElement(
      "div",
      { class: "pm-toolbar" },
      // Clear
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "Clear styles from selected text or text under caret",
          onclick: clearSelection,
        }),
        "Clear",
      ),
      // Header1
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "apply header1 to selected text",
          onclick: surroundSelection("h1"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-type-h1" viewBox="0 0 16 16" aria-hidden="true"><path d="M8.637
        13V3.669H7.379V7.62H2.758V3.67H1.5V13h1.258V8.728h4.62V13h1.259zm5.329
        0V3.669h-1.244L10.5 5.316v1.265l2.16-1.565h.062V13h1.244z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "header1"),
      ),
      // Header2
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "apply header2 to selected text",
          onclick: surroundSelection("h2"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-type-h2" viewBox="0 0 16 16" aria-hidden="true"><path d="M7.638
        13V3.669H6.38V7.62H1.759V3.67H.5V13h1.258V8.728h4.62V13h1.259zm3.022-6.733v-.048c0-.889.63-1.668
        1.716-1.668.957 0 1.675.608 1.675 1.572 0 .855-.554 1.504-1.067 2.085l-3.513
        3.999V13H15.5v-1.094h-4.245v-.075l2.481-2.844c.875-.998 1.586-1.784
        1.586-2.953 0-1.463-1.155-2.556-2.919-2.556-1.941 0-2.966 1.326-2.966 2.74v.049h1.223z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "header2"),
      ),
      // Bold
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "bold selected text",
          onclick: surroundSelection("strong"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-type-bold" viewBox="0 0 16 16" aria-hidden="true"><path d="M8.21 13c2.106 0
        3.412-1.087 3.412-2.823 0-1.306-.984-2.283-2.324-2.386v-.055a2.176 2.176 0 0 0
        1.852-2.14c0-1.51-1.162-2.46-3.014-2.46H3.843V13H8.21zM5.908 4.674h1.696c.963 0 1.517.451 1.517
        1.244 0 .834-.629 1.32-1.73 1.32H5.908V4.673zm0 6.788V8.598h1.73c1.217 0 1.88.492 1.88 1.415
        0 .943-.643 1.449-1.832 1.449H5.907z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "bold"),
      ),
      // Italic
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "italic selected text",
          onclick: surroundSelection("em"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-type-italic" viewBox="0 0 16 16" aria-hidden="true"><path d="M7.991
        11.674L9.53 4.455c.123-.595.246-.71 1.347-.807l.11-.52H7.211l-.11.52c1.06.096 1.128.212 1.005.807L6.57
        11.674c-.123.595-.246.71-1.346.806l-.11.52h3.774l.11-.52c-1.06-.095-1.129-.211-1.006-.806z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "italic"),
      ),
      // Underline
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "underline selected text",
          onclick: surroundSelection("u"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-type-underline" viewBox="0 0 16 16" aria-hidden="true"><path d="M5.313 3.136h-1.23V9.54c0 2.105
        1.47 3.623 3.917 3.623s3.917-1.518 3.917-3.623V3.136h-1.23v6.323c0 1.49-.978 2.57-2.687 2.57-1.709
        0-2.687-1.08-2.687-2.57V3.136zM12.5 15h-9v-1h9v1z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "underline"),
      ),
      // Strikeout
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "strikeout selected text",
          onclick: surroundSelection("strike"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-type-strikethrough" viewBox="0 0 16 16" aria-hidden="true"><path d="M6.333 5.686c0
        .31.083.581.27.814H5.166a2.776 2.776 0 0 1-.099-.76c0-1.627 1.436-2.768 3.48-2.768 1.969 0 3.39 1.175
        3.445 2.85h-1.23c-.11-1.08-.964-1.743-2.25-1.743-1.23 0-2.18.602-2.18 1.607zm2.194 7.478c-2.153
        0-3.589-1.107-3.705-2.81h1.23c.144 1.06 1.129 1.703 2.544 1.703 1.34 0 2.31-.705 2.31-1.675
        0-.827-.547-1.374-1.914-1.675L8.046 8.5H1v-1h14v1h-3.504c.468.437.675.994.675 1.697 0
        1.826-1.436 2.967-3.644 2.967z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "strikeout"),
      ),
      // Un-list
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "remove list under caret",
          onclick: unlist,
        }),
        "Un-list",
      ),
      // Bullet list
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "bullet list selected text",
          onclick: listifySelection("ul"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-list-ul" viewBox="0 0 16 16" aria-hidden="true"><path fill-rule="evenodd" d="M5 11.5a.5.5 0 0 1
        .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5
        0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm-3 1a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm0 4a1 1 0 1 0 0-2
        1 1 0 0 0 0 2zm0 4a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "bullet list"),
      ),
      // Number list
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "number list selected text",
          onclick: listifySelection("ol"),
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
        class="bi bi-list-ol" viewBox="0 0 16 16" aria-hidden="true"><path fill-rule="evenodd" d="M5 11.5a.5.5 0 0 1
        .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5zm0-4a.5.5 0
        0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5z"></path><path d="M1.713 11.865v-.474H2c.217 0 .363-.137.363-.317
        0-.185-.158-.31-.361-.31-.223 0-.367.152-.373.31h-.59c.016-.467.373-.787.986-.787.588-.002.954.291.957.703a.595.595
        0 0 1-.492.594v.033a.615.615 0 0 1 .569.631c.003.533-.502.8-1.051.8-.656 0-1-.37-1.008-.794h.582c.008.178.186.306.422.309.254
        0 .424-.145.422-.35-.002-.195-.155-.348-.414-.348h-.3zm-.004-4.699h-.604v-.035c0-.408.295-.844.958-.844.583 0 .96.326.96.756 0
        .389-.257.617-.476.848l-.537.572v.03h1.054V9H1.143v-.395l.957-.99c.138-.142.293-.304.293-.508 0-.18-.147-.32-.342-.32a.33.33
        0 0 0-.342.338v.041zM2.564 5h-.635V2.924h-.031l-.598.42v-.567l.629-.443h.635V5z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "number list"),
      ),
      // Insert link
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "insert link under caret",
          onclick: null,
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor"
        xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img" preserveAspectRatio="xMidYMid meet"
        class="iconify iconify--mdi" viewBox="0 0 24 24" aria-hidden="true"><path d="M10.6 13.4a1 1 0 0 1-1.4 1.4a4.8
        4.8 0 0 1 0-7l3.5-3.6a5.1 5.1 0 0 1 7.1 0a5.1 5.1 0 0 1 0 7.1l-1.5 1.5a6.4 6.4 0 0 0-.4-2.4l.5-.5a3.2 3.2 0 0
        0 0-4.3a3.2 3.2 0 0 0-4.3 0l-3.5 3.6a2.9 2.9 0 0 0 0 4.2M23 18v2h-3v3h-2v-3h-3v-2h3v-3h2v3m-3.8-4.3a4.8 4.8 0
        0 0-1.4-4.5a1 1 0 0 0-1.4 1.4a2.9 2.9 0 0 1 0 4.2l-3.5 3.6a3.2 3.2 0 0 1-4.3 0a3.2 3.2 0 0 1 0-4.3l.5-.4a7.3
        7.3 0 0 1-.4-2.5l-1.5 1.5a5.1 5.1 0 0 0 0 7.1a5.1 5.1 0 0 0 7.1 0l1.8-1.8a6 6 0 0 1 3.1-4.3z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "insert link"),
      ),
      // Modify link
      pmCreateElement(
        "button",
        buttonAttributes({
          title: "modify link under caret",
          onclick: null,
        }),
        pmCreateElement(`<svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="currentColor"
        xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img" preserveAspectRatio="xMidYMid meet"
        class="iconify iconify--mdi" viewBox="0 0 24 24" aria-hidden="true"><path d="M10.59 13.41c.41.39.41 1.03 0
        1.42c-.39.39-1.03.39-1.42 0a5.003 5.003 0 0 1 0-7.07l3.54-3.54a5.003 5.003 0 0 1 7.07 0a5.003 5.003 0 0 1 0
        7.07l-1.49 1.49c.01-.82-.12-1.64-.4-2.42l.47-.48a2.982 2.982 0 0 0 0-4.24a2.982 2.982 0 0 0-4.24 0l-3.53
        3.53a2.982 2.982 0 0 0 0 4.24m2.82-4.24c.39-.39 1.03-.39 1.42 0a5.003 5.003 0 0 1 0 7.07l-3.54 3.54a5.003
        5.003 0 0 1-7.07 0a5.003 5.003 0 0 1 0-7.07l1.49-1.49c-.01.82.12 1.64.4 2.43l-.47.47a2.982 2.982 0 0 0 0
        4.24a2.982 2.982 0 0 0 4.24 0l3.53-3.53a2.982 2.982 0 0 0 0-4.24a.973.973 0 0 1 0-1.42z"></path></svg>`),
        pmCreateElement("span", labelAttributes, "modify link"),
      ),
      // Delete
      deleteButton,
      // Save
      pmCreateElement("button", buttonAttributes({ title: "save changes to page", onclick: save }), "Save"),
    );
    const toolbarPadding = pmCreateElement("div", { class: "pm-toolbar-padding" });
    document.querySelector("body")?.append(toolbar, toolbarPadding);
    window.addEventListener("load", resizeToolbarPadding);
    window.addEventListener("resize", resizeToolbarPadding);

    function resizeToolbarPadding() {
      const toolbarStyle = window.getComputedStyle(toolbar);
      const height =
        toolbar.offsetHeight +
        parseInt(toolbarStyle.getPropertyValue("margin-top"), 10) +
        parseInt(toolbarStyle.getPropertyValue("margin-bottom"), 10);
      toolbarPadding.style.marginBottom = `${height}px`;
    }

    // https://developer.mozilla.org/en-US/docs/Glossary/Empty_element
    const singletonElements = new Set(
      new Array().concat(
        ["AREA", "BASE", "BR", "COL", "EMBED", "HR", "IMG", "INPUT"],
        ["LINK", "META", "PARAM", "SOURCE", "TRACK", "WBR"],
      ),
    );

    // https://developer.mozilla.org/en-US/docs/Web/HTML/Block-level_elements
    const blockElements = new Set(
      new Array().concat(
        ["ADDRESS", "ARTICLE", "ASIDE", "BLOCKQUOTE", "DETAILS", "DIALOG"],
        ["DD", "DIV", "DL", "DT", "FIELDSET", "FIGCAPTION", "FIGURE", "FOOTER"],
        ["FORM", "H1", "H2", "H3", "H4", "H5", "H6", "HEADER", "HGROUP", "HR"],
        ["LI", "MAIN", "NAV", "OL", "P", "PRE", "SECTION", "TABLE", "UL"],
      ),
    );

    function isContentEditable(node) {
      return node?.getAttribute?.("contenteditable") === "true";
    }

    function getContenteditableToplevelNode(node, offset) {
      if (!node) {
        return undefined;
      }
      if (isContentEditable(node)) {
        return node.childNodes[offset];
      }
      if (node.nodeName === "BODY" || node.nodeName === "HTML") {
        return undefined;
      }
      while (node.parentNode && node.parentNode.nodeName !== "BODY") {
        if (isContentEditable(node.parentNode)) {
          return node;
        }
        node = node.parentNode;
      }
      return undefined;
    }

    function inContentEditable(range) {
      const start = getContenteditableToplevelNode(range.startContainer, range.startOffset);
      const end = getContenteditableToplevelNode(range.endContainer, range.endOffset);
      return start && end && start.parentNode === end.parentNode;
    }

    function removeEmptyTextnodes(nodes) {
      let result = [];
      for (const node of nodes) {
        if (node.nodeName === "#text" && node.textContent.trim() === "") {
          continue;
        }
        result.push(node);
      }
      return result;
    }

    function getListToplevelNode(node) {
      if (!node) {
        return undefined;
      }
      if (node.nodeName === "LI" || node.nodeName === "BODY" || node.nodeName === "HTML") {
        return undefined;
      }
      while (node.parentNode && node.parentNode.nodeName !== "BODY") {
        if (node.parentNode.nodeName === "LI") {
          return node;
        }
        node = node.parentNode;
      }
      return undefined;
    }

    function clearTags(node) {
      const fragment = document.createDocumentFragment();
      if (!node) {
        return fragment;
      }
      let stack = [];
      let texts = [];
      stack.unshift(node);
      while (stack.length !== 0) {
        let head = stack.shift();
        if (head.nodeName === "#text") {
          texts.push(head.textContent);
          continue;
        }
        if (singletonElements.has(head)) {
          if (texts.length > 0) {
            fragment.append(document.createTextNode(texts.join("")));
            texts = [];
          }
          fragment.append(head.cloneNode());
          continue;
        }
        stack.unshift(...head.childNodes);
      }
      if (texts.length > 0) {
        fragment.append(document.createTextNode(texts.join("")));
      }
      return fragment;
    }

    function surroundSelection(tag) {
      return function () {
        let sel = window.getSelection();
        if (!sel.anchorNode) {
          console.log("one");
          return; // nothing selected and caret not present in document
        }
        let range = sel.getRangeAt(0);
        if (range.collapsed) {
          console.log("two");
          return; // nothing selected
        }
        if (!inContentEditable(range)) {
          console.log("three");
          return; // not in contenteditable
        }
        let node = document.createElement(tag);
        node.append(range.extractContents());
        range.insertNode(node);
      };
    }

    function listifySelection(tag) {
      return function () {
        let sel = window.getSelection();
        if (!sel.anchorNode) {
          return; // nothing selected and caret not present in document
        }
        let range = sel.getRangeAt(0);
        if (range.collapsed) {
          return; // nothing selected
        }
        if (!inContentEditable(range)) {
          return; // not in contenteditable
        }
        const listNodes = [];
        const nodes = removeEmptyTextnodes(range.extractContents().childNodes);
        let fragment = null;
        {
          // *** isolate ***
          for (const node of nodes) {
            if (!blockElements.has(node) && node.nodeName !== "BR") {
              if (!fragment) {
                fragment = document.createDocumentFragment();
              }
              fragment.append(node);
              continue;
            }
            if (fragment) {
              listNodes.push(fragment);
              fragment = null;
            }
            if (node.nodeName !== "BR") {
              listNodes.push(node);
            }
          }
          if (fragment) {
            listNodes.push(fragment);
          }
          // *** isolate ***
        }
        const list = document.createElement(tag);
        for (const node of listNodes) {
          const li = document.createElement("li");
          li.append(node);
          list.append(li);
        }
        range.insertNode(list);
      };
    }

    function clearSelection() {
      const sel = window.getSelection();
      if (!sel.anchorNode) {
        return; // nothing selected and caret not present in document
      }
      const range = sel.getRangeAt(0);
      if (!inContentEditable(range)) {
        return; // not in contenteditable
      }

      // case 1: single caret (nothing selected)
      if (range.collapsed) {
        // keep going up until the first contenteditable element or <li> element
        const contenteditableToplevel = getContenteditableToplevelNode(range.startContainer, range.startOffset);
        const listToplevel = getListToplevelNode(range.startContainer);
        if (listToplevel) {
          listToplevel.replaceWith(clearTags(listToplevel));
        } else if (contenteditableToplevel) {
          contenteditableToplevel.replaceWith(clearTags(contenteditableToplevel));
        }
        return;
      }

      // case 2: selection within a single (non-contenteditable) node
      const parent = range.startContainer.parentNode;
      if (!isContentEditable(parent) && !isContentEditable(range.startContainer)) {
        const isTextNodeSelection = range.startContainer === range.endContainer;
        const isNodeSelection = parent.firstChild === range.startContainer && parent.lastChild === range.endContainer;
        if (isTextNodeSelection || isNodeSelection) {
          parent.replaceWith(clearTags(parent));
          return;
        }
      }

      let toplevels = range.commonAncestorContainer.childNodes;
      const toplevelStart = getContenteditableToplevelNode(range.startContainer, range.startOffset);
      const toplevelEnd = getContenteditableToplevelNode(range.endContainer, range.endOffset);
      // const fragment = document.createDocumentFragment();
      let [startIndex, endIndex] = [undefined, undefined];
      let liCount = 0;
      for (const [i, toplevel] of toplevels.entries()) {
        // if toplevel nodes
        if (toplevel == toplevelStart) {
          startIndex = i;
        } else if (toplevel == toplevelEnd) {
          endIndex = i;
        }
        // if list
        if (toplevel.nodeName === "LI") {
          liCount++;
          // const contents = toplevel.childNodes[0].cloneNode();
          // if (contents.nodeName === "#text" && i > 0) {
          //   fragment.append(document.createElement("br"));
          // }
          // fragment.append(contents);
        }
      }

      // case 3: selection spanning multiple toplevel nodes
      if (startIndex !== undefined && endIndex !== undefined) {
        for (let i = startIndex; i <= endIndex; i++) {
          toplevels[i].replaceWith(clearTags(toplevels[i]));
        }
        return;
      }

      // case 4: selection within a list
      if (liCount === toplevels.length) {
        // TODO: this should clear the styles across multiple <li> elements without purging the <li> tags themselves.
        // constrain our actions to the parent <li> element
        const liToplevel = getListToplevelNode(range.startContainer);
        liToplevel?.replaceWith(clearTags(liToplevel));
        // range.commonAncestorContainer.replaceWith(fragment);
        return;
      }
    }

    function unlist() {
      const sel = window.getSelection();
      if (!sel.anchorNode) {
        return; // nothing selected and caret not present in document
      }
      const range = sel.getRangeAt(0);
      if (!inContentEditable(range)) {
        return; // not in contenteditable
      }
      // case 1: single caret (nothing selected)
      if (range.collapsed) {
        // get the parent <ul>/<ol> element, if any
        const list = getListToplevelNode(range.startContainer)?.parentNode?.parentNode;
        let prevItemIsBlockElement = true;
        if (list) {
          const fragment = document.createDocumentFragment();
          const lis = removeEmptyTextnodes(list.childNodes);
          for (const li of lis) {
            if (li.nodeName !== "LI") {
              continue;
            }
            // if the previous item is not a block element, we insert a manual
            // linebreak <br> so that the current element starts on a new line
            if (!prevItemIsBlockElement) {
              fragment.append(document.createElement("br"));
            }
            prevItemIsBlockElement = blockElements.has(li.childNodes[li.childNodes.length - 1]);
            fragment.append(...li.childNodes);
          }
          list.replaceWith(fragment);
        }
        return;
      }

      // case 2: selection spans multiple <li>s
      // TODO: merge each selected <li> into the previous <li>
      // if no previous <li>, just dump the contents outside the <ul> (right before it)
      // handle the shitty <br> edge cases again
    }

    function deleteElement() {
      deleteMode = true;
      document.body.style.cursor = "crosshair";
      deleteButton.style.filter = "invert(100%)";
    }
    document.addEventListener("mousedown", function () {
      if (deleteMode) {
        deleteMode = false;
        document.body.style.cursor = "auto";
        document.querySelectorAll("#pm-delete-overlay").forEach((node) => node.remove());
        deleteButton.style.filter = "";
      }
    });

    function getRowDetails(node) {
      if (!node) {
        return undefined;
      }
      if (node.nodeName === "BODY" || node.nodeName === "HTML") {
        return undefined;
      }
      while (node.parentNode && node.parentNode.nodeName !== "BODY") {
        const name = node.parentNode.getAttribute("data-pm.row");
        const indexStr = node.parentNode.getAttribute("data-pm.rowindex");
        if (name && indexStr) {
          const index = parseInt(indexStr, 10);
          if (isNaN(index)) {
            throw new Error(`${indexStr} is not a number`);
          }
          return { name, index };
        }
        node = node.parentNode;
      }
      return undefined;
    }

    async function save() {
      const data = {};
      const indextracker = {};
      const pageID = window.Env("PageID").replace(/\/edit$/, "");
      for (const node of document.querySelectorAll("[data-pm\\.row]")) {
        if (node.getAttribute("hidden") !== null) {
          continue;
        }
        const rowname = node.getAttribute("data-pm.row");
        const index = indextracker[rowname] || 0;
        node.setAttribute("data-pm.rowindex", `${index}`);
        indextracker[rowname] = index + 1;
      }
      for (const node of document.querySelectorAll("[data-pm\\.key]")) {
        const ID = node.getAttribute("data-pm.id") || pageID;
        const key = node.getAttribute("data-pm.key");
        const value = node.innerHTML;
        set(data, [ID, key], value);
      }
      for (const node of document.querySelectorAll("[data-pm\\.row\\.key],[data-pm\\.row\\.href]")) {
        const row = getRowDetails(node);
        if (!row) {
          continue;
        }
        const ID = node.getAttribute("data-pm.id") || pageID;
        const key = node.getAttribute("data-pm.row.key");
        const hrefKey = node.getAttribute("data-pm.row.href");
        const value = node.innerHTML;
        const hrefValue = node.getAttribute("href");
        if (key) {
          set(data, [ID, row.name, row.index, key], value);
        }
        if (hrefKey) {
          set(data, [ID, row.name, row.index, hrefKey], hrefValue);
        }
      }
      const imgs = [];
      for (const canvas of document.querySelectorAll("canvas[data-pm\\.img\\.upload]")) {
        const url = canvas.getAttribute("data-pm.img.upload");
        const blob = await new Promise((resolve) => canvas.toBlob(resolve));
        imgs.push({ url, blob });
      }
      console.log(data);
      console.log(imgs);
      const formdata = new FormData();
      for (const [key, value] of Object.entries(data)) {
        formdata.append(key, JSON.stringify(value));
      }
      for (const img of imgs) {
        formdata.append("imgs[]", img.blob, img.url);
      }
      // Display the key/value pairs
      for (const [key, value] of formdata.entries()) {
        console.log(key + ", " + value);
      }
      const res = await fetch("/upload", {
        method: "POST",
        body: formdata,
      });
      console.log(res);
    }

    function pathToKeys(path) {
      let keys = path
        .replace(/\[|\]\[|\]/g, ".") // replace array brackets with dot
        .replace(/\.{2,}/g, ".") // replace multiple dots with one dot
        .replace(/^\.+|\.+$|\s*/g, "") // don't want leading dots, trailing dots or whitespaces
        .split(".");
      // convert number strings into numbers
      for (const [index, value] of keys.entries()) {
        const number = parseInt(value, 10);
        if (!isNaN(number)) {
          keys[index] = number;
        }
      }
      return keys;
    }

    function set(obj, path, value) {
      const keys = typeof path === "string" ? pathToKeys(path) : [...path];
      let key = keys.shift();
      while (keys.length > 0) {
        let nextkey = keys.shift();
        if (Number.isInteger(nextkey) && !Array.isArray(obj[key])) {
          obj[key] = [];
        } else if (typeof nextkey === "string" && typeof obj[key] !== "object" && obj[key] !== null) {
          obj[key] = {};
        }
        obj = obj[key]; // point the obj reference at the next element
        key = nextkey;
      }
      obj[key] = value;
    }

    function get(obj, path) {
      const keys = typeof path === "string" ? pathToKeys(path) : [...path];
      while (keys.length > 0) {
        const key = keys.shift();
        obj = obj[key];
        if (obj === null || obj === undefined) {
          return obj;
        }
      }
      return obj;
    }

    return toolbar;
  }

  function pmContenteditable(node) {
    node.setAttribute("contenteditable", true);
    node.classList.add("contenteditable");
  }

  function pmImagePicker(img) {
    // the image that we render onto the canvas
    let sourceImage = pmCreateElement("img", {
      src: img.src,
      "data-pm.img.upload": img.getAttribute("data-pm.img.upload") || "",
      "data-pm.img.fallback": img.getAttribute("data-pm.img.fallback") || "",
      onload: initialRender,
      onerror: fallbackRender,
    });
    let dragging = false; // track mouse dragging inside the canvas
    let outOfBoundsDragging = false; // track mouse dragging outside the canvas
    let destX = 0; // x-coord of top-left corner of sourceImage on the canvas
    let destY = 0; // y-coord of top-left corner of sourceImage on the canvas
    let scaleX = 1; // width-scaling factor of sourceImage on the canvas
    let scaleY = 1; // height-scaling factor of sourceImage on the canvas
    let lastWidthSliderValue = 0; // track widthSlider values
    let lastHeightSliderValue = 0; // track heightSlider values
    let lastMouseX, lastMouseY; // track mouse coords in the canvas
    const canvas = pmCreateElement("canvas", {
      "data-pm.img.upload": img.getAttribute("data-pm.img.upload") || "",
      width: img.width,
      height: img.height,
      onmousedown: mousedown,
      onmousemove: mousemove,
      onmouseup: mouseup,
      onmouseout: mouseout,
      onmouseenter: mouseenter,
    });
    const keepAspectRatio = pmCreateElement("input", {
      id: Math.random().toString(36).substring(2),
      type: "checkbox",
      style: { "margin-right": "0.5rem" },
      checked: true,
    });
    const scaleMax = 2;
    const sliderMax = 100;
    const sliderMin = 0;
    const sliderStep = (scaleMax - 1) / (sliderMax - sliderMin);
    const widthSlider = pmCreateElement("input", {
      type: "range",
      min: sliderMin,
      max: sliderMax,
      value: 0,
      oninput: resizewidth,
    });
    const heightSlider = pmCreateElement("input", {
      type: "range",
      min: sliderMin,
      max: sliderMax,
      value: 0,
      oninput: resizeheight,
    });
    const imgUpload = pmCreateElement("input", {
      type: "file",
      accept: "image/png, image/jpeg",
      style: {
        position: "absolute",
        top: "10px",
        left: "10px",
        color: "white",
        "font-family": "sans-serif",
        "text-shadow": "-1px 0 black, 0 1px black, 1px 0 black, 0 -1px black",
      },
      oninput: uploadimage,
    });
    const resizer = pmCreateElement(
      "div",
      {
        style: {
          position: "absolute",
          bottom: "10px",
          left: "10px",
          color: "white",
          "font-family": "sans-serif",
          "text-shadow": "-1px 0 black, 0 1px black, 1px 0 black, 0 -1px black",
        },
      },
      pmCreateElement(
        "div",
        {},
        keepAspectRatio,
        pmCreateElement("label", { for: keepAspectRatio.id }, "Lock aspect ratio"),
      ),
      pmCreateElement(
        "div",
        { style: { display: "flex", "align-items": "center", "justify-content": "space-between" } },
        pmCreateElement("span", { style: { "margin-right": "0.5rem" } }, "Width"),
        widthSlider,
      ),
      pmCreateElement(
        "div",
        { style: { display: "flex", "align-items": "center", "justify-content": "space-between" } },
        pmCreateElement("span", { style: { "margin-right": "0.5rem" } }, "Height"),
        heightSlider,
      ),
    );
    const imgpicker = pmCreateElement(
      "div",
      {
        class: img.classList,
        style: {
          display: "inline-block",
          position: "relative",
          width: `${img.width}px`,
          height: `${img.height}px`,
        },
      },
      canvas,
      imgUpload,
      resizer,
    );
    imgpicker.classList.add("imgpicker");
    document.addEventListener("mouseup", function (event) {
      if (imgpicker.contains(event.target)) {
        return;
      }
      dragging = false;
      outOfBoundsDragging = false;
    });

    function initialRender() {
      render();
      img.replaceWith(imgpicker);
    }

    function fallbackRender() {
      const fallbackSrc = sourceImage.getAttribute("data-pm.img.fallback");
      const fallbackImage = document.createElement("img");
      fallbackImage.src = fallbackSrc;
      fallbackImage.addEventListener("load", function () {
        sourceImage = fallbackImage;
        render();
      });
      img.replaceWith(imgpicker);
    }

    function render() {
      const scaledWidth = canvas.width * scaleX;
      const scaledHeight = canvas.height * scaleY;
      const minDestX = canvas.width - scaledWidth;
      const maxDestX = 0;
      const minDestY = canvas.height - scaledHeight;
      const maxDestY = 0;
      const ctx = canvas.getContext("2d");
      // Boundary checks
      if (destX < minDestX) {
        destX = minDestX;
      }
      if (destX > maxDestX) {
        destX = maxDestX;
      }
      if (destY < minDestY) {
        destY = minDestY;
      }
      if (destY > maxDestY) {
        destY = maxDestY;
      }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(sourceImage, destX, destY, scaledWidth, scaledHeight);
      window.sourceImage = sourceImage;
    }

    async function uploadimage() {
      const file = imgUpload.files[0];
      if (file === null || file === undefined) {
        return;
      }
      sourceImage = await createImageBitmap(file);
      destX = 0;
      destY = 0;
      scaleX = 1;
      scaleY = 1;
      widthSlider.value = 0;
      heightSlider.value = 0;
      render();
    }

    function resizewidth() {
      const widthSliderValue = parseInt(widthSlider.value, 10);
      const sliderDelta = widthSliderValue - lastWidthSliderValue;
      const widthDelta = canvas.width * sliderStep * sliderDelta;
      scaleX = 1 + widthSliderValue * sliderStep;
      destX -= widthDelta / 2;
      lastWidthSliderValue = widthSliderValue;
      if (keepAspectRatio.checked) {
        let heightSliderValue = parseInt(heightSlider.value, 10) + sliderDelta;
        // Boundary checks
        if (heightSliderValue < sliderMin) {
          heightSliderValue = sliderMin;
        }
        if (heightSliderValue > sliderMax) {
          heightSliderValue = sliderMax;
        }
        heightSlider.value = `${heightSliderValue}`;
        const heightDelta = canvas.width * sliderStep * (heightSliderValue - lastHeightSliderValue);
        scaleY = 1 + heightSliderValue * sliderStep;
        destY -= heightDelta / 2;
        lastHeightSliderValue = heightSliderValue;
      }
      render();
    }

    function resizeheight() {
      const heightSliderValue = parseInt(heightSlider.value, 10);
      const sliderDelta = heightSliderValue - lastHeightSliderValue;
      const heightDelta = canvas.width * sliderStep * sliderDelta;
      scaleY = 1 + heightSliderValue * sliderStep;
      destY -= heightDelta / 2;
      lastHeightSliderValue = heightSliderValue;
      if (keepAspectRatio.checked) {
        let widthSliderValue = parseInt(widthSlider.value, 10) + sliderDelta;
        // Boundary checks
        if (widthSliderValue < sliderMin) {
          widthSliderValue = sliderMin;
        }
        if (widthSliderValue > sliderMax) {
          widthSliderValue = sliderMax;
        }
        widthSlider.value = `${widthSliderValue}`;
        const widthDelta = canvas.width * sliderStep * (widthSliderValue - lastWidthSliderValue);
        scaleX = 1 + widthSliderValue * sliderStep;
        destX -= widthDelta / 2;
        lastWidthSliderValue = widthSliderValue;
      }
      render();
    }

    function mousedown(event) {
      const rect = canvas.getBoundingClientRect();
      lastMouseX = event.clientX - rect.left;
      lastMouseY = event.clientY - rect.top;
      dragging = true;
    }

    function mousemove(event) {
      if (!dragging) {
        return;
      }
      const rect = canvas.getBoundingClientRect();
      const mouseX = event.clientX - rect.left;
      const mouseY = event.clientY - rect.top;
      const deltaX = mouseX - lastMouseX;
      const deltaY = mouseY - lastMouseY;
      destX += deltaX;
      destY += deltaY;
      lastMouseX = mouseX;
      lastMouseY = mouseY;
      render();
    }

    function mouseup() {
      dragging = false;
    }

    function mouseout() {
      if (dragging) {
        dragging = false;
        outOfBoundsDragging = true;
      }
    }

    function mouseenter() {
      if (outOfBoundsDragging) {
        outOfBoundsDragging = false;
        dragging = true;
      }
    }
  }
});

// for debugging
window.addEventListener("keypress", function (event) {
  // boilerplate
  let sel = window.getSelection();
  if (!sel.anchorNode) {
    return;
  }
  let range = sel.getRangeAt(0);
  if (event.ctrlKey && event.key === "0") {
    window.sel = sel;
    window.range = range;
    console.log("sel", sel);
    console.log("range", range);
    console.log("startContainer", range.startContainer);
    console.log("endContainer", range.endContainer);
    console.log("commonAncestorContainer", range.commonAncestorContainer.childNodes);
  } else if (event.ctrlKey && event.key === "9") {
    window.docfrag = range.cloneContents();
    console.log("cloneContents", range.cloneContents());
  }
});
