import shelve

class Products:
    count_id = 0
    # product_count_db_filename = 'product_count.db'
    def __init__(self, name, price, quantity, country, type, dietary):
        self.__id = id
        self.__name = name
        self.__price = price
        self.__quantity = quantity
        self.__country = country
        self.__type = type
        self.__dietary = dietary
        self.__url = None

    def generate_product_id(self):
        db = shelve.open('products.db', 'c')
        products_dict = {}
        try:
            products_dict = db['Products']
        except:
            print('Error in retrieving products from products.db.')

        number_product_id = len(products_dict)
        count_id = number_product_id + 1
        db.close()
        return count_id
        
    def set_id(self, id):
        self.__id = id

    def set_name(self, name):
        self.__name = name
    
    def set_price(self, price):
        self.__price = price
    
    def set_quantity(self, quantity):
        self.__quantity = quantity

    def set_country(self, country):
        self.__country = country

    def set_type(self, type):
        self.__type = type

    def set_dietary(self, dietary):
        self.__dietary = dietary

    def set_url(self, url):
        self.__url = url

    def get_id(self):
        return self.__id

    def get_name(self):
        return self.__name

    def get_price(self):
        return self.__price
        
    def get_quantity(self):
        return self.__quantity
    
    def get_country(self):
        return self.__country

    def get_type(self):
        return self.__type

    def get_dietary(self):
        return self.__dietary
    
    def get_url(self):
        return self.__url

class Cart():
    def __init__(self, cart_quantity, cart_id):
        self.__cart_quantity = cart_quantity
        self.__cart_id = cart_id

    def set_cart_quantity(self, cart_quantity):
        self.__cart_quantity = cart_quantity

    def set_cart_id(self, cart_id):
        self.__cart_id = cart_id

    def get_cart_quantity(self):
        return self.__cart_quantity
    
    def get_cart_id(self):
        return self.__cart_id
    
# enumerated_dict = {}
# product1 = Products( "Product1", 10, 5, "Country1", "Brand1", "Dietary1")
# product2 = Products("Product2", 15, 8, "Country2", "Brand2", "Dietary2")
# product3 = Products( "Product3", 20, 3, "Country3", "Brand3", "Dietary3")
# products_dict = {product1.get_id(): product1, product2.get_id(): product2, product3.get_id(): product3}
# remove_id = 1
# for key in products_dict:
#     if remove_id > 0:
#         if remove_id in products_dict:
#             remove_id_list = [remove_id]

# products_dict.pop(remove_id)
# print(list(products_dict.keys())[-1])
# print(products_dict)

# for key in products_dict:
#     if key != list(products_dict.keys())[-1]:
#         if key >= 0:
#             key_to_check_positive = key + 1
#     if key > 1:
#         key_to_check_negative = key - 1


#     if key_to_check_positive not in products_dict:
#         enumerated_dict = {index: products_dict[key] for index, key in enumerate(products_dict)}
#     if key_to_check_negative not in products_dict:
#         enumerated_dict = {index: products_dict[key] for index, key in enumerate(products_dict)}
    