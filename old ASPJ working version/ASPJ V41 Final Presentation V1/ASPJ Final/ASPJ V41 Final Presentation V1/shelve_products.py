import random
import shelve
from Products import Products
products_dict = {}
db = shelve.open('products.db', 'c')
try:
    products_dict = db['Products']

except:
    print('Error in retrieving products from products.db.')
Product = Products('','','','','','')

# Snacks
products_dict_new = {}
def remove_non_ascii(text):
    return ''.join(i for i in text if ord(i) < 128)
product_id = 8722
new_product_names_list = []
new_product_price_list = []
temp_list = []
new_product_dietary_list = []
country_list = ['Singapore','Japan', 'China', 'India']

# Name
with open("product_names.txt", "r") as product_names:
    product_names_list = product_names.readlines()
    for name in product_names_list:
        final_name = name.replace('\n', '')
        new_product_names_list.append(final_name)
# Name END

# Price
with open('prices.txt', 'r') as product_price:
    product_price_list = product_price.readlines()
    for price in product_price_list:
        final_price = price.replace('\n', '')
        final_price = final_price.replace('$','')
        final_price = float(final_price)
        new_product_price_list.append(final_price)
# Price END
        
# Dietary
with open('product_amounts.txt', 'r') as product_dietary:
    product_dietary_list = product_dietary.readlines()
    for dietary in product_dietary_list:
        temp_list.append(dietary.strip("\n"))
    for i in range(len(temp_list)):
        if "Halal" in temp_list[i]:
            temp_list[i - 1] += " • Halal"
        elif "Organic" in temp_list[i]:
            temp_list[i - 1] += " • Organic"
        elif "/pc" in temp_list[i]:
            temp_list[i - 1] += f" • {temp_list[i][1:]}"
    temp_list = [product_amt for product_amt in temp_list if "•Halal" not in product_amt]
    temp_list = [product_amt for product_amt in temp_list if "•Organic" not in product_amt]
    temp_list = [product_amt for product_amt in temp_list if "•$" not in product_amt]
    for item in temp_list:
        final_item = remove_non_ascii(item)
        final_item = ' '.join(final_item.split())
        if 'Halal' in final_item:
            final_item = final_item[-5:]
            new_product_dietary_list.append(final_item)
        elif 'Organic' in final_item:
            final_item = final_item[-7:]
            new_product_dietary_list.append(final_item)
        else:
            final_item = 'Halal_&_Organic'
            new_product_dietary_list.append(final_item)

    #     new_product_dietary_list.append(final_item)
    # for item in new_product_dietary_list:
    #     print(item)
# Dietary END

if len(new_product_names_list) != len(new_product_price_list):
    print("Error: Length of product names list doesn't match the length of product prices list.")
else:
    for (name, price, dietary) in zip(new_product_names_list, new_product_price_list, new_product_dietary_list):
        random_quantity = random.randint(1, 1000)
        random_country_num = random.randint(0,3)
        random_country = country_list[random_country_num]
        Product = Products(name,price,random_quantity,random_country,'Beauty_&_personal_care',dietary)
        products_dict_new[product_id] = Product
        product_id += 1 

# products_dict.update(products_dict_new)
# db['Products'] = products_dict
# print(db['Products'])



# How to use:
        
# Change the frozen to the correct type
# Change the product_id at the top to one after current id