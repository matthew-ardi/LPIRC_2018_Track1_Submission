from django.contrib import admin

# Register your models here.
from .models import RegisterUser
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin  # Important, dont remove
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.http import HttpResponse
from app.models import Sponsor, Organizer
import csv


"""User Admin"""
# combine 2 model so that info from RegisterUser can be modified inside User Admin
class UserInline(admin.TabularInline):
    model = RegisterUser


# actions
def email_users(self, request, queryset):
    list = queryset.values('email', 'id')

    user_id_selected = []
    for l in list:
        user_id_selected.append(l['id'])

    # open a session and render the email_selected to admin_email view
    request.session['user_id_selected'] = user_id_selected
    return redirect('admin_email')
email_users.short_description = "Email Users"


def export_csv(self, request, queryset):
    # https://docs.djangoproject.com/en/1.11/howto/outputting-csv/
    # https://stackoverflow.com/questions/18685223/how-to-export-django-model-data-into-csv-file

    # setup csv writer
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment;filename=LPIRC_user_list.csv'
    writer = csv.writer(response)

    required_field_names = ['last_login', 'is_superuser', 'username', 'first_name', 'last_name', 'email', 'is_staff',
                            'is_active', 'date_joined']

    optional_field_names = ['contract_signed']

    field_names = required_field_names.copy()
    for field in optional_field_names:
        field_names.append(field)
    writer.writerow(field_names)

    # output data
    for obj in queryset:
        required_info = [getattr(obj, field) for field in required_field_names]
        try:
            optional = RegisterUser.objects.get(user=obj)  # get optional info of user
            optional_info = [getattr(optional, field) for field in optional_field_names]
        except:
            optional_info = ['' for field in optional_field_names]
        for data in optional_info:
            required_info.append(data)
        writer.writerow(required_info)
    return response
export_csv.short_description = "Export selected user as csv"

# model
class UserAdmin(admin.ModelAdmin):
    list_display = (
        'username',
        'email',
        'first_name',
        'last_name',
        'contract_signed',
        'date_joined',
        'is_staff',
        'is_active'
    )
    list_select_related = ('registeruser',)
    inlines = [
        UserInline,
    ]
    #readonly_fields = ("username", "password", )
    actions = [email_users, export_csv]

    def contract_signed(self, instance):
        return instance.registeruser.contract_signed
    contract_signed.boolean = True
    contract_signed.short_description = 'contract_signed'

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(UserAdmin, self).get_inline_instances(request, obj)

class SponsorAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'image_link'
    )

    def image_link(self, obj):
        return obj.image_link

class OrganizerAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'image_link'
    )

    def image_link(self, obj):
        return obj.image_link

admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.register(Sponsor, SponsorAdmin)
admin.site.register(Organizer, OrganizerAdmin)

