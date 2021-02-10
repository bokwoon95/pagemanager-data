DELETE FROM pm_routes;

-- content
INSERT INTO pm_routes
    (url, content)
VALUES
    ('/hello/', '<h1>this is hello</h1>')
ON CONFLICT (url) DO UPDATE SET
    content = EXCLUDED.content
;

-- template
INSERT INTO pm_routes
    (url, template_namespace, template_name)
VALUES
    ('/posts', 'plainsimple/', 'index.html')
ON CONFLICT (url) DO UPDATE SET
    template_namespace = EXCLUDED.template_namespace
    ,template_name = EXCLUDED.template_name
;
