
from wtforms import Form, SelectField




class RestaurantSearchForm(Form):
    seating = [('yes', 'no')]
    take_out = [('yes','no')]
    delivery = [('yes', 'no')]
    curbside_pickup = [('yes','no')]
    social_distancing = [('yes', 'no')]
    disinfecting = [('yes','no')]




    select = SelectField('Seating:', seating=seating)
    select2 = SelectField('Take out:', take_out=take_out)
    select3 = SelectField('Delivery:', delivery=delivery)
    select4 = SelectField('Curbside pickup:', curbside_pickup=curbside_pickup)
    select5 = SelectField('Social Distancing:', social_distancing=social_distancing)
    select6 = SelectField('Disinfecting:', disinfecting=disinfecting)