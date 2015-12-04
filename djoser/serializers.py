from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from . import constants, utils

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            User._meta.pk.name,
            'email',
        )
        read_only_fields = (
            'email',
        )


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    referral = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            'email',
            User._meta.pk.name,
            'password',
            'referral'
        )

    def create(self, validated_data):
        referrer = validated_data.pop('referral', None)
        user = User.objects.create_user(**validated_data)

        if referrer and User.objects.filter(email=referrer).count() == 1:
            user.referrer = User.objects.get(email=referrer)
            user.credits += 10
            user.save()

            user.referrer.credits += 10
            user.referrer.save()
        elif referrer in ['sagarmathalbv']:
            user.credits += 10
            user.save()

        return user


class UserRegistrationTokenSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    token = serializers.CharField(source="auth_token.key", read_only=True)
    referral = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            'email',
            User._meta.pk.name,
            'password',
            'token',
            'referral'
        )

    def create(self, validated_data):
        referrer = validated_data.pop('referral', None)

        user = User.objects.create_user(**validated_data)

        if referrer and User.objects.filter(email=referrer).count() == 1:
            user.referrer = User.objects.get(email=referrer)
            user.credits += 10
            user.save()

            user.referrer.credits += 10
            user.referrer.save()
        elif referrer in ['sagarmathalbv']:
            user.credits += 10
            user.save()

        Token.objects.get_or_create(user=user)
        return user


class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(required=False, style={'input_type': 'password'})

    default_error_messages = {
        'inactive_account': constants.INACTIVE_ACCOUNT_ERROR,
        'invalid_credentials': constants.INVALID_CREDENTIALS_ERROR,
    }

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.user = None
        self.fields['email'] = serializers.CharField(required=False)

    def validate(self, attrs):
        self.user = authenticate(username=attrs.get('email'), password=attrs.get('password'))
        if self.user:
            if not self.user.is_active:
                raise serializers.ValidationError(self.error_messages['inactive_account'])
            return attrs
        else:
            raise serializers.ValidationError(self.error_messages['invalid_credentials'])


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class UidAndTokenSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()

    default_error_messages = {
        'invalid_token': constants.INVALID_TOKEN_ERROR
    }

    def validate_uid(self, value):
        try:
            uid = utils.decode_uid(value)
            self.user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError) as error:
            raise serializers.ValidationError(error)
        return value

    def validate(self, attrs):
        attrs = super(UidAndTokenSerializer, self).validate(attrs)
        if not self.context['view'].token_generator.check_token(self.user, attrs['token']):
            raise serializers.ValidationError(self.error_messages['invalid_token'])
        return attrs


class PasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(style={'input_type': 'password'})


class PasswordRetypeSerializer(PasswordSerializer):
    re_new_password = serializers.CharField(style={'input_type': 'password'})

    default_error_messages = {
        'password_mismatch': constants.PASSWORD_MISMATCH_ERROR,
    }

    def validate(self, attrs):
        attrs = super(PasswordRetypeSerializer, self).validate(attrs)
        if attrs['new_password'] != attrs['re_new_password']:
            raise serializers.ValidationError(self.error_messages['password_mismatch'])
        return attrs


class CurrentPasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(style={'input_type': 'password'})

    default_error_messages = {
        'invalid_password': constants.INVALID_PASSWORD_ERROR,
    }

    def validate_current_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError(self.error_messages['invalid_password'])
        return value


class SetPasswordSerializer(PasswordSerializer, CurrentPasswordSerializer):
    pass


class SetPasswordRetypeSerializer(PasswordRetypeSerializer, CurrentPasswordSerializer):
    pass


class PasswordResetConfirmSerializer(UidAndTokenSerializer, PasswordSerializer):
    pass


class PasswordResetConfirmRetypeSerializer(UidAndTokenSerializer, PasswordRetypeSerializer):
    pass


class SetUsernameSerializer(serializers.ModelSerializer, CurrentPasswordSerializer):

    class Meta(object):
        model = User
        fields = (
            'email',
            'current_password',
        )

    def __init__(self, *args, **kwargs):
        super(SetUsernameSerializer, self).__init__(*args, **kwargs)
        self.fields['new_' + 'email'] = self.fields['email']
        del self.fields['email']


class SetUsernameRetypeSerializer(SetUsernameSerializer):
    default_error_messages = {
        'username_mismatch': constants.USERNAME_MISMATCH_ERROR.format('email'),
    }

    def __init__(self, *args, **kwargs):
        super(SetUsernameRetypeSerializer, self).__init__(*args, **kwargs)
        self.fields['re_new_' + 'email'] = serializers.CharField()

    def validate(self, attrs):
        attrs = super(SetUsernameRetypeSerializer, self).validate(attrs)
        new_username = attrs['email']
        if new_username != attrs['re_new_' + 'email']:
            raise serializers.ValidationError(self.error_messages['username_mismatch'].format('email'))
        return attrs


class TokenSerializer(serializers.ModelSerializer):
    auth_token = serializers.CharField(source='key')

    class Meta:
        model = Token
        fields = (
            'auth_token',
        )
