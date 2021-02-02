return {
  metadata: "Chua Bok Woon",
  templates: {
    "/pm-assets/plainsimple/post-index.html": {
      include: [
        "/pm-assets/plainsimple/header.html",
        "/pm-assets/plainsimple/footer.html",
        "/pm-assets/plainsimple/style.css",
      ],
      contentSecurityPolicy: {
        "script-src": ["stackpath.bootstrapcdn.com", "code.jquery.com"],
        "style-src": ["stackpath.bootstrapcdn.com", "fonts.googleapis.com"],
        "img-src": ["source.unsplash.com", "images.unsplash.com"],
        "font-src": ["fonts.gstatic.com"],
      },
    },
  },
};
