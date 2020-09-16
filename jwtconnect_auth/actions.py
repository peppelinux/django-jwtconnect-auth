from . models import JWTConnectAuthToken


def remove_older_tokens(user):
    """
    remove all the tokens but last, newer
    """
    user_tokens = JWTConnectAuthToken.objects.filter(user=user)
    last_token = user_tokens.order_by('issued_at').last()
    user_tokens = user_tokens.exclude(pk=last_token.pk)
    cnt = user_tokens.count()
    user_tokens.delete()
    return cnt
