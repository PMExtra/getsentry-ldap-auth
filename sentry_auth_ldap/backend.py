from django_auth_ldap.backend import LDAPBackend
from django.conf import settings
from sentry.models import (
    Organization,
    OrganizationMember,
    UserEmail,
    UserOption,
)


def _get_effective_sentry_role(ldap_user):
    role_priority_order = [
        'member',
        'admin',
        'manager',
        'owner',
    ]

    role_mapping = getattr(settings, 'AUTH_LDAP_SENTRY_GROUP_ROLE_MAPPING', None)
    if not role_mapping:
        return None

    group_names = ldap_user.group_names
    if not group_names:
        return None

    applicable_roles = [role for role, groups in role_mapping.items() if group_names.intersection(groups)]
    if not applicable_roles:
        return None

    highest_role = [role for role in role_priority_order if role in applicable_roles][-1]
    return highest_role


def _find_default_organization():
    organization_slug = getattr(settings, 'AUTH_LDAP_SENTRY_DEFAULT_ORGANIZATION', None)
    if organization_slug:
        return Organization.objects.filter(slug=organization_slug).first()

    # For backward compatibility
    organization_name = getattr(settings, 'AUTH_LDAP_DEFAULT_SENTRY_ORGANIZATION', None)
    if organization_name:
        return Organization.objects.filter(name=organization_name).first()

    return None


class SentryLdapBackend(LDAPBackend):
    def get_or_build_user(self, username, ldap_user):
        (user, built) = super().get_or_build_user(username, ldap_user)

        user.is_managed = True

        # Add the user email address
        mail_attr_name = self.settings.USER_ATTR_MAP.get('email', 'mail')
        mail_attr = ldap_user.attrs.get(mail_attr_name)
        if mail_attr:
            email = mail_attr[0]
        elif hasattr(settings, 'AUTH_LDAP_DEFAULT_EMAIL_DOMAIN'):
            email = username + '@' + settings.AUTH_LDAP_DEFAULT_EMAIL_DOMAIN
        else:
            email = None

        if email:
            user.email = email

        user.save()

        if mail_attr and getattr(settings, 'AUTH_LDAP_MAIL_VERIFIED', False):
            defaults = { 'is_verified': True }
        else:
            defaults = None

        for mail in mail_attr or [email]:
            UserEmail.objects.update_or_create(defaults=defaults, user=user, email=mail)

        organization = _find_default_organization()
        # Allow modifying OrganizationMember after initial creation
        if organization and not OrganizationMember.objects.filter(organization=organization, user_id=user.id).exists():
            OrganizationMember.objects.create(
                organization=organization,
                user_id=user.id,
                role: _get_effective_sentry_role(ldap_user) or getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_ROLE_TYPE', None),
                has_global_access: getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False),
                flags: getattr(OrganizationMember.flags, 'sso:linked'),
            )

        if not getattr(settings, 'AUTH_LDAP_SENTRY_SUBSCRIBE_BY_DEFAULT', True):
            UserOption.objects.set_value(
                user=user,
                project=None,
                key='subscribe_by_default',
                value='0',
            )

        return (user, built)
