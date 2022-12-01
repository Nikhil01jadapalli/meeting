from django.shortcuts import render

# Create your views here.
import email
from urllib import response
from django.shortcuts import render
from rest_framework import generics, status, views, permissions

# from core.common.response import return_error_response
from .serializers import (RegisterSerializer, SetNewPasswordSerializer, MeetingSerializer,ResetPasswordEmailRequestSerializer,  LoginSerializer, LogoutSerializer)
from rest_framework.response import Response  
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt , datetime
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
import os
from rest_framework import status
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
# from core.common.logger import get_custom_logger
# from core.common.response import return_error_response
from .serializers import *
from rest_framework.views import APIView


# log = get_custom_logger()

# Create your views here.
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER

class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


# class RegisterView(generics.GenericAPIView):

#     serializer_class = RegisterSerializer
#     renderer_classes = (UserRenderer,)

#     def post(self, request):
#         user = request.data
#         serializer = self.serializer_class(data=user)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         user_data = serializer.data
#         user = User.objects.get(email=user_data['email']) 
#         # token = RefreshToken.for_user(user).access_token
#         current_site = get_current_site(request).domain
#         # relativeLink = reverse('email-verify')
#         relativeLink = reverse('login')
#         absurl = 'http://'+current_site+relativeLink
#         # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
#         email_body = 'Hi '+user.username  +'\n Thank you for registering with Terralogic Meet. Please find the credentials below for your future reference.\n '+ \
#             ' Use the link below to verify your email \n'+'\n Username :'+user.username + '\n Password :'+'*********'  + \
#               "\n URl:"+absurl + '\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
#                    '\n Thanks,' +'\n Terralogic Team'            
#         data = {'email_body': email_body, 'to_email': user.email,
#                 'email_subject': 'Registration successfull'}

#         Util.send_email(data)
#         return Response(user_data, status=status.HTTP_201_CREATED)



# class LoginAPIView(generics.GenericAPIView):
#     serializer_class = LoginSerializer
#     def post(self,request):
#         data=request.data
#         email=data.get('email',None)
#         password=data.get('password',None)
#         serializer=self.serializer_class(data=data)
#         if serializer.is_valid(raise_exception=True):
#             serializer.save()
#         payload = jwt_payload_handler(User)
#         token = jwt_encode_handler(payload)
#         context = {
#             'name': User.email,
#             'token' :token
#         }
#         response_validator=LoginSerializer(data=context)
#         if not response_validator.is_valid():
#             return return_error_response(response_validator.error_messages,data=response_validator.errors)
#         return response(
#                 code=200,
#                 status=200,
#                 message="USER_LOGIN_SUCCESS",
#                 data=response_validator.validated_data,
#             )

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email']) 
        # token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        # relativeLink = reverse('email-verify')
        relativeLink = reverse('login')
        absurl = 'http://'+current_site+relativeLink
        # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+user.username  +'\n Thank you for registering with Terralogic Meet. Please find the credentials below for your future reference.\n '+ \
            ' Use the link below to verify your email \n'+'\n Username :'+user.username + '\n Password :'+'*********'  + \
              "\n URl:"+absurl + '\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
                   '\n Thanks,' +'\n Terralogic Team'            
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Registration successfull'}

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------------------------------------------

class MeetingView(generics.GenericAPIView):

    serializer_class = MeetingSerializer
    # renderer_classes = (UserRenderer,)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'login')
            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hi,'+ user.username +'\n' + 'Use below link to join meeting  \n' + \
                absurl+"?redirect_url="+redirect_url +'\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
                    '\n Thanks,' +'\n Terralogic Team' 
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Invitation For Terralogic Meet'} 
            Util.send_email(data) 
        return Response({'success': 'We have sent you a link for attend meeting'}, status=status.HTTP_200_OK) 

        

        # if User.objects.filter(email=email).exists():
        #     user = User.objects.get(email=email)
        #     # uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        #     # token = PasswordResetTokenGenerator().make_token(user)
        #     current_site = get_current_site(
        #         request=request).domain
        #     relativeLink = reverse(
        #         'login')
        #     redirect_url = request.data.get('redirect_url', '')
        #     absurl = 'http://'+current_site + relativeLink
        #     email_body = 'Hi,'+ user.username +'\n' + 'Use below link to join meeting  \n' + \
        #         absurl+"?redirect_url="+redirect_url +'\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
        #             '\n Thanks,' +'\n Terralogic Team' 
        #     data = {'email_body': email_body, 'to_email': user.email,
        #             'email_subject': 'Invitation For Terralogic Meet'} 
        #     Util.send_email(data)  
        # return Response({'success': 'We have sent you a link for attend meeting'}, status=status.HTTP_200_OK) 

#------------------------------------------------------------------------------------------------------------------

    # def post(self, request):
    #     user = request.data
    #     serializer = self.serializer_class(data=user)
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     user_data = serializer.data
    #     user = User.objects.get(email=user_data['email']) 
    #     # token = RefreshToken.for_user(user).access_token 
    #     current_site = get_current_site(request).domain 
    #     # relativeLink = reverse('email-verify') 
    #     relativeLink = reverse('login')
    #     absurl = 'http://'+current_site+relativeLink
    #     # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
    #     email_body = 'Hi '+user.username  +'\n Use the link below to Attend meeting'+ \
    #           "\n URl:"+absurl + '\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
    #                '\n Thanks,' +'\n Terralogic Team'            
    #     data = {'email_body': email_body, 'to_email': user.email,
    #             'email_subject': 'Invitation for meeting'}

    #     Util.send_email(data)
    #     return Response(user_data, status=status.HTTP_201_CREATED)

# ----------------------------------------------------------------------------------------------------------------

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token,
            'username':user.username
        }
        return response




# class LoginView(generics.GenericAPIView):
#     serializer_class = LoginSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)