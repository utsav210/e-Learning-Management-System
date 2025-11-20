from django.conf import settings
import secrets

class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        nonce = secrets.token_urlsafe(16)
        setattr(request, 'csp_nonce', nonce)
        default_src = getattr(settings, 'CSP_DEFAULT_SRC', ("'self'",))
        base_script_src = getattr(settings, 'CSP_SCRIPT_SRC', default_src)
        script_src = base_script_src + (f"'nonce-{nonce}'",)
        style_src = getattr(settings, 'CSP_STYLE_SRC', default_src)
        img_src = getattr(settings, 'CSP_IMG_SRC', default_src)
        font_src = getattr(settings, 'CSP_FONT_SRC', default_src)
        connect_src = getattr(settings, 'CSP_CONNECT_SRC', default_src)
        frame_src = getattr(settings, 'CSP_FRAME_SRC', ("'none'",))
        media_src = getattr(settings, 'CSP_MEDIA_SRC', default_src)
        object_src = getattr(settings, 'CSP_OBJECT_SRC', ("'none'",))

        def join(vals):
            return ' '.join(vals)

        csp = []
        csp.append(f"default-src {join(default_src)}")
        csp.append(f"script-src {join(script_src)}")
        csp.append(f"style-src {join(style_src)}")
        csp.append(f"img-src {join(img_src)}")
        csp.append(f"font-src {join(font_src)}")
        csp.append(f"connect-src {join(connect_src)}")
        csp.append(f"frame-src {join(frame_src)}")
        csp.append(f"media-src {join(media_src)}")
        csp.append(f"object-src {join(object_src)}")

        response['Content-Security-Policy'] = '; '.join(csp)
        return response